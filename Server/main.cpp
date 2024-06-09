#include "../shared-libs/configmanager.hpp"
#include "../shared-libs/cryptomanager.hpp"
#include "libs/ClientManager.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <mutex>

const std::string configPath = "config.conf";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort", "maxClients"};
std::mutex connectionMutex;
int activeConnections = 0;

int main() {
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

        /* CryptoManager cryptoManager("server.priv", "server.pub");
        if (cryptoManager.generateRSAKey()) {
            std::cout << "> Chiavi server: generate" << std::endl;
        } else {
            std::cout << "> Chiavi server: già presenti" << std::endl;
        } */

        std::cout << std::endl;

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
                    Packet fullPacket(PacketType::SERVER_FULL);
                    std::vector<char> serialized = fullPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) < 0) {
                        std::cerr << "[!] Impossibile scrivere al client." << std::endl;
                        break;
                    }
                    close(client_socket);
                    continue;
                } else {
                    Packet helloPacket(PacketType::HELLO);
                    std::vector<char> serialized = helloPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) < 0) {
                        std::cerr << "[!] Impossibile scrivere al client." << std::endl;
                        break;
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