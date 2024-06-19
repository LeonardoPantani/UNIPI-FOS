#include "libs/ServerManager.hpp"
#include "../shared-libs/configmanager.hpp"
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

// Intervallo di default tra una connessione e l'altra
const int connectionInterval = 5;

// La f. handle_server legge questa variabile per capire se terminare
volatile sig_atomic_t clientRunning = true;

// Handler per il segnale CTRL+C (SIGINT)
void signalHandler(int s);
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
        std::cout << "> IP da raggiungere: " << serverIP << std::endl;
        std::cout << "> Porta: " << serverPort << std::endl;
        std::cout << "> Max. tentativi connessione: " << maxAttempsToConnect << std::endl;
        std::cout << std::endl;

        // lettura certificati
        crypto = new CryptoClient("../shared-certificates/ca.pem", "../shared-certificates/crl.pem", "client.pem");

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
            return 0;
        }

        std::cout << "> Connessione stabilita." << std::endl;

        // gestione thread inputhandler
        std::thread userInputThread(handle_user_input, sock, std::ref(clientRunning));

        // avvio thread gestione server
        handle_server(sock, clientRunning);

        // unirsi al thread dell'input utente prima di terminare
        if (userInputThread.joinable()) {
            userInputThread.join();
        }

        close(sock);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}