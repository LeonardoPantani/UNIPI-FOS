#include "ServerManager.hpp"
#include <iostream>
#include <unistd.h>
#include <cstring>

void handle_server(int server_socket) {
    try {
        char buffer[PACKET_SIZE];
        memset(buffer, 0, sizeof(buffer));
        
        int bytes_read = read(server_socket, buffer, sizeof(buffer));
        if (bytes_read == PACKET_SIZE) {
            Packet packet = Packet::deserialize(buffer, bytes_read);
            if (packet.type == PacketType::SERVER_FULL) {
                throw std::runtime_error("Il server non accetta ulteriori client al momento.");
            } else {
                std::cout << "Server > " << packet.getTypeAsString() << std::endl;
            }
        } else {
            throw std::runtime_error("Che bell'inizio! Impossibile continuare a causa di un errore di comunicazione.");
        }

        std::string userInput;
        while (true) {
            std::cout << "Input: ";
            std::getline(std::cin, userInput);

            if (userInput == "") {
                std::cout << "[!] Inserisci un messaggio." << std::endl;
                continue;
            } else if (userInput.length() > DATA_SIZE-1) {
                std::cout << "[!] Il messaggio supera il limite di " << (DATA_SIZE-1) << " caratteri." << std::endl;
                continue;
            }

            Packet otherPacket(PacketType::OTHER, userInput);
            std::vector<char> serializedOther = otherPacket.serialize();
            if (write(server_socket, serializedOther.data(), serializedOther.size()) == -1) {
                std::cerr << "[!] Errore nella scrittura sul server_socket." << std::endl;
                break;
            }
        }

        close(server_socket);
    } catch (const std::exception& e) {
        std::cerr << "[!] Si è verificato un errore grave: " << e.what() << std::endl;
        exit(1);
    }
}
