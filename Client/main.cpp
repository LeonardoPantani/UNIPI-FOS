#include "libs/ServerManager.hpp"
#include "../shared-libs/ConfigManager.hpp"
#include "libs/CryptoClient.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <csignal>
#include <thread>

// Percorso del file di configurazione
const std::string configPath = "config.json";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort", "maxAttempsToConnect"};

// Percorso certificati e chiavi
const std::string certCaPath = "../shared-certificates/ca.pem";
const std::string certCRLPath = "../shared-certificates/crl.pem";
const std::string ownCertPath = "client_cert.pem";
const std::string ownPrivKeyPath = "client_priv.pem";

// Intervallo di default tra una connessione e l'altra (in secondi)
const int connectionInterval = 5;

// La funzione handle_server legge questa variabile per capire se terminare
volatile sig_atomic_t clientRunning = true;

// Handler per il segnale CTRL+C (SIGINT)
void signalHandler(int s) {
    clientRunning = false;
    std::cout << "\n" << "> Terminazione client." << std::endl;
}

// lettura certificati
CryptoClient* crypto = nullptr;

int main() {
    // gestione segnale interruzione
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = signalHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    try {
        ConfigManager configManager(configPath, configKeys);

        std::string configVersion = configManager.getString("configVersion");
        std::string serverIP = configManager.getString("serverIP");
        int serverPort = configManager.getInt("serverPort");
        int maxAttempsToConnect = configManager.getInt("maxAttempsToConnect");
        if (maxAttempsToConnect > 10) throw std::runtime_error("Il parametro di configurazione 'maxAttempsToConnect' non può essere maggiore di 10.");

        std::cout << "FILE DI CONFIGURAZIONE CLIENT (v." << configVersion <<") CARICATO: " << std::endl;
        std::cout << "├ IP da raggiungere: " << serverIP << std::endl;
        std::cout << "├ Porta: " << serverPort << std::endl;
        std::cout << "├ Max. tentativi connessione: " << maxAttempsToConnect << std::endl;
        std::cout << "│" << std::endl;
        std::cout << "└ Per uscire dal programma premi 'CTRL/CMD' e 'C' contemporaneamente." << std::endl;
        std::cout << std::endl;

        // istanziazione classe cryptoclient
        crypto = new CryptoClient(certCaPath, certCRLPath, ownCertPath, ownPrivKeyPath);

        int sock = 0;
        while (clientRunning) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) { continue; }

            sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(serverPort);
            server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str());

            if (connect(sock, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) == -1) {
                if(--maxAttempsToConnect == 0) throw std::runtime_error("Impossibile connettersi. Il numero di tentativi massimo è stato raggiunto.");
                std::cerr << "[!] Impossibile connettersi. Nuovo tentativo in " << connectionInterval << "s..." << std::endl;
                close(sock);
                sleep(connectionInterval);
                continue;
            }
            break;
        }

        if (!clientRunning) {
            close(sock);
            delete crypto;
            return 0;
        }

        std::cout << "> Server trovato." << std::endl;

        // gestione thread inputhandler
        std::thread userInputThread(handle_user_input, sock, std::ref(clientRunning));

        // chiamata la funzione principale handle_server
        handle_server(sock, clientRunning);

        // si attende che il thread inputhandler termini prima di chiudere il programma
        if (userInputThread.joinable()) {
            userInputThread.join();
        }

        delete crypto;

        close(sock);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << std::endl;
        return 1;
    }
    return 0;
}