#include "../shared-libs/configmanager.hpp"
#include "../shared-libs/cryptomanager.hpp"

#include "libs/ThreadPool.hpp"
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

// Pool di thread
ThreadPool* pool = nullptr;

// Handler per il segnale CTRL+C (SIGINT)
void signalHandler(int s) {
    if (pool) {
        pool->stopAll(); // TODO: se si esegue CTRL+C e nessun client si è mai connesso è necessario eseguirlo due volte invece di una sola
    }
}

// Percorso del file di configurazione
const std::string configPath = "config.json";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort", "threadPoolSize"};

// Memoria persistente
const std::string dataFilePath = "persistentMemory.json"; // file memoria persistente
const std::string keyFilePath = "persistentMemory.key"; // file contenente la chiave per decriptare e criptare

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
        int threadPoolSize = configManager.getInt("threadPoolSize");

        std::cout << "FILE DI CONFIGURAZIONE SERVER (v." << configVersion <<") CARICATO: " << std::endl;
        std::cout << "> Indirizzo IP: " << serverIP << std::endl;
        std::cout << "> Porta: " << serverPort << std::endl;
        std::cout << "> Dimensione pool di thread: " << threadPoolSize << std::endl;
        std::cout << std::endl;

        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        int new_server_socket;
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
        int addrLen = sizeof(server_addr);

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            throw std::runtime_error("Binding fallito.");
        }

        if (listen(server_socket, 100) < 0) {
            throw std::runtime_error("Listen fallito.");
        }

        pool = new ThreadPool(threadPoolSize);

        while (true) {
            new_server_socket = accept(server_socket, (struct sockaddr *)&server_addr, (socklen_t *)&addrLen);
            if (new_server_socket < 0) {
                break;
            }

            (*pool).enqueue([new_server_socket](std::thread::id id) { handle_client(new_server_socket, id); });
        }

        delete pool;
        close(server_socket);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}