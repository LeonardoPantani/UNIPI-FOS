#include "../shared-libs/configmanager.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <cstring>
#include <mutex>

const char* blockExtraClientsMSG = "Server pieno.";
const std::string configPath = "config.conf";
std::mutex connectionMutex;
int activeConnections = 0;

void handle_client(int client_socket) {
    {
        std::lock_guard<std::mutex> lock(connectionMutex);
        ++activeConnections;
    }

    try {
        char buffer[2048];
        while (true) {
            memset(buffer, 0, 2048);
            int bytes_read = read(client_socket, buffer, 2048 - 1);
            if (bytes_read <= 0) break;

            std::cout << "Client > " << buffer << std::endl;
            if (write(client_socket, buffer, bytes_read) < 0) {
                std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                break;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    std::cout << "Connessione col client terminata." << std::endl;
    close(client_socket);

    {
        std::lock_guard<std::mutex> lock(connectionMutex);
        --activeConnections;
    }
}

int main() {
    try {
        ConfigManager configManager(configPath);
        std::string configVersion = configManager.getString("configVersion");
        std::string serverIP = configManager.getString("serverIP");
        int serverPort = configManager.getInt("serverPort");
        int maxClients = configManager.getInt("maxClients");

        std::cout << "FILE DI CONFIGURAZIONE SERVER (v." << configVersion <<") CARICATO: " << std::endl;
        std::cout << "> Indirizzo IP: " << serverIP << std::endl;
        std::cout << "> Porta: " << serverPort << std::endl;
        std::cout << "> Max numero client: " << maxClients << std::endl;

        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1) {
            throw std::runtime_error("Creazione socket fallita.");
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(serverPort);
        server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str());

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            throw std::runtime_error("Binding fallito.");
        }

        if (listen(server_socket, maxClients) < 0) {
            throw std::runtime_error("Listen fallito.");
        }

        while (true) {
            int client_socket = accept(server_socket, NULL, NULL);
            if (client_socket < 0) {
                std::cerr << "[!] Impossibile accettare client." << std::endl;
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(connectionMutex);
                if (activeConnections >= maxClients) {
                    if (write(client_socket, blockExtraClientsMSG, strlen(blockExtraClientsMSG)) < 0) {
                        std::cerr << "[!] Impossibile rispondere al client." << std::endl;
                    }
                    close(client_socket);
                    continue;
                } else {
                    const char* msg = "Salve!";
                    if(write(client_socket, msg, strlen(msg)) < 0) {
                        std::cerr << "[!] Impossibile contattare il client." << std::endl;
                        close(client_socket);
                        continue;
                    }
                }
            }

            std::thread t(handle_client, client_socket);
            t.detach();
        }

        close(server_socket);
    } catch (const std::exception& e) {
        std::cerr << "[!] Si è verificato un errore grave: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}