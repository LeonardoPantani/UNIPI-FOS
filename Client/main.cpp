#include "../shared-libs/configmanager.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>

const std::string configPath = "config.conf";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort"};
const int connectionInterval = 5;

int main() {
    try {
        ConfigManager configManager(configPath, configKeys);
        if (!configManager.checkVersion()) { return 1; }

        
        std::string configVersion = configManager.getString("configVersion");
        std::string serverIP = configManager.getString("serverIP");
        int serverPort = configManager.getInt("serverPort");

        std::cout << "FILE DI CONFIGURAZIONE CLIENT (v." << configVersion <<") CARICATO: " << std::endl;
        std::cout << "> IP da raggiungere: " << serverIP << std::endl;
        std::cout << "> Porta: " << serverPort << std::endl;
        std::cout << std::endl;

        int sock;
        while (true) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) { continue; }

            sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(serverPort);
            server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str());

            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                std::cerr << "[!] Impossibile connettersi. Nuovo tentativo in " << connectionInterval << "s..." << std::endl;
                close(sock);
                sleep(connectionInterval);
                continue;
            }
            break;
        }

        std::cout << "> Connessione stabilita." << std::endl;

        char buffer[2048] = {0};
        int bytes_read = read(sock, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            if(strcmp(buffer, "Server pieno.") == 0) {
                throw std::runtime_error("Il server non accetta ulteriori client al momento.");
            } else {
                std::cout << "Server > " << buffer << std::endl;
            }
        } else {
            throw std::runtime_error("Che bell'inizio! Impossibile continuare a causa di un errore di comunicazione.");
        }

        std::string userInput;
        while (true) {
            std::cout << "Input: ";
            std::getline(std::cin, userInput);
            send(sock, userInput.c_str(), userInput.length(), 0);

            memset(buffer, 0, sizeof(buffer));
            bytes_read = read(sock, buffer, sizeof(buffer) - 1);
            if (bytes_read > 0) {
                std::cout << "Server > " << buffer << std::endl;
            } else {
                throw std::runtime_error("Impossibile leggere la risposta o connessione chiusa dal server.");
            }
        }

        close(sock);
    } catch (const std::exception& e) {
        std::cerr << "[!] Si è verificato un errore grave: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
