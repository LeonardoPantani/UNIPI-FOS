#include "ClientManager.hpp"
#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>

void handle_client(int client_socket, PersistentMemory pm) {
    try {
        char buffer[PACKET_SIZE];
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            int bytes_read = read(client_socket, buffer, sizeof(buffer));
            if (bytes_read != PACKET_SIZE) break;
            Packet packet = Packet::deserialize(buffer, bytes_read);

            std::cout << "Client > " << packet.getTypeAsString() << std::endl;
            switch (packet.type) {
                case PacketType::HELLO:
                    {
                        Packet helloPacket(PacketType::HELLO);
                        std::vector<char> serialized = helloPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) < 0) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }
                    break;
                case PacketType::BYE:
                case PacketType::SERVER_FULL:
                case PacketType::SERVER_CLOSING:
                case PacketType::LOGIN_REQUEST:
                case PacketType::REGISTER_REQUEST:
                case PacketType::LOGIN_OK:
                case PacketType::REGISTER_OK:
                case PacketType::ERROR:
                case PacketType::OTHER: 
                    std::cout << "Contenuto > " << packet.getContent() << std::endl;
                    break;
                case PacketType::BBS_LIST:
                case PacketType::BBS_GET:
                case PacketType::BBS_ADD:
                default:
                    break;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    std::cout << "> Connessione col client terminata." << std::endl;
    close(client_socket);
}
