#include "libs/ServerManager.hpp"
#include "../shared-libs/configmanager.hpp"
#include "../shared-libs/cryptomanager.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <vector>

const std::string configPath = "config.conf";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort", "maxAttempsToConnect"};
const int connectionInterval = 5;

int main() {
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

        int sock;
        while (true) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock == -1) { continue; }

            sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(serverPort);
            server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str());

            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                if(--maxAttempsToConnect == 0) throw std::runtime_error("Impossibile connettersi. Il numero di tentativi massimo è stato raggiunto.");
                std::cerr << "[!] Impossibile connettersi. Nuovo tentativo in " << connectionInterval << "s..." << std::endl;
                close(sock);
                sleep(connectionInterval);
                continue;
            }
            break;
        }

        std::cout << "> Connessione stabilita." << std::endl;

        // mando il pacchetto HELLO come saluto
        Packet helloPacket(PacketType::HELLO);
        std::vector<char> serializedHello = helloPacket.serialize();
        send(sock, serializedHello.data(), serializedHello.size(), 0);

        handle_server(sock);

        close(sock);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
