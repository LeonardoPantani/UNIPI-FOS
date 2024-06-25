#include "../shared-libs/ConfigManager.hpp"
#include "libs/CryptoServer.hpp"
#include "libs/ClientManager.hpp"
#include "libs/PersistentMemory.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <mutex>
#include <csignal>
#include <atomic>

// Handler per il segnale CTRL+C (SIGINT)
std::vector<std::thread> threads;
volatile std::atomic<bool> serverRunning(true);

void signalHandler(int s) {
    std::cout << "\n> Terminazione server." << std::endl;
    serverRunning.store(false);
}

// Percorso del file di configurazione
const std::string configPath = "config.json";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort", "maxClients"};

// Percorso certificati e chiavi
const std::string certCaPath = "../shared-certificates/ca.pem";
const std::string certCRLPath = "../shared-certificates/crl.pem";
const std::string ownCertPath = "server_cert.pem";
const std::string ownPrivKeyPath = "server_priv.pem";

// Controllo limite connessioni
volatile std::atomic<int> activeConnections = 0;

// Memoria persistente
PersistentMemory* memory = nullptr;
const std::string dataFilePath = "persistentMemory.json"; // file memoria persistente
const std::string keyFilePath = "persistentMemory.key"; // file contenente la chiave per decriptare e criptare

// lettura certificati
CryptoServer* crypto = nullptr;

// Codice principale
int main() {
    // gestione segnale interruzione
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = signalHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    // codice server
    try {
        ConfigManager configManager(configPath, configKeys);
        std::string configVersion = configManager.getString("configVersion");
        std::string serverIP = configManager.getString("serverIP");
        int serverPort = configManager.getInt("serverPort");
        int maxClients = configManager.getInt("maxClients");

        std::cout << "FILE DI CONFIGURAZIONE SERVER (v." << configVersion <<") CARICATO: " << std::endl;
        std::cout << "> Indirizzo IP: " << serverIP << std::endl;
        std::cout << "> Porta: " << serverPort << std::endl;
        std::cout << "> Max numero client: " << maxClients << std::endl;
        std::cout << std::endl;

        crypto = new CryptoServer(certCaPath, certCRLPath, ownCertPath, ownPrivKeyPath);

        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        if (server_socket == -1) {
            throw std::runtime_error("Creazione socket fallita.");
        }

        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            throw std::runtime_error("Operazione setsockopt SO_REUSEADDR fallita.");
        }
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
            throw std::runtime_error("Operazione setsockopt SO_REUSEPORT fallita.");
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(serverPort);
        server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str());

        if (bind(server_socket, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
            throw std::runtime_error("Binding fallito.");
        }

        if (listen(server_socket, 100) < 0) {
            throw std::runtime_error("Listen fallito.");
        }

        memory = new PersistentMemory(dataFilePath, keyFilePath);

        while (serverRunning) {
            int client_socket = accept(server_socket, NULL, NULL);
            if (client_socket < 0) {
                if (errno == EINTR && !serverRunning) {
                    break;
                }
                std::cerr << "Errore durante l'accettazione della connessione." << std::endl;
                continue;
            }

            if (activeConnections >= maxClients) {
                Packet fullPacket(PacketType::SERVER_FULL);
                std::vector<char> serialized = fullPacket.serialize();
                WRITE(client_socket, serialized);
                close(client_socket);
                continue;
            }

            ++activeConnections;

            threads.emplace_back(handle_client, client_socket);
        }

        // unisco tutti i thread prima di chiudere il server
        for (std::thread &t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        delete memory;
        delete crypto;
        close(server_socket);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
