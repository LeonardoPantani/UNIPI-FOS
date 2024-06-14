#include <atomic>
#include <sys/select.h>
#include "ClientManager.hpp"

extern PersistentMemory* memory;
extern volatile std::atomic<bool> serverRunning;

void handle_client(int client_socket) {
    try {
        char buffer[PACKET_SIZE];
        
        while (serverRunning) {
            memset(buffer, 0, sizeof(buffer));

            // Configura il file descriptor set per la select
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_socket, &read_fds);

            // Imposta il timeout della select (qui 1 secondi come esempio)
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            // Chiama select per vedere se ci sono dati pronti per la lettura
            int select_result = select(client_socket + 1, &read_fds, NULL, NULL, &timeout);

            if (select_result == -1) {
                throw std::runtime_error("Errore select.");
            } else if (select_result == 0) {
                continue;
            }

            // Se siamo qui, significa che ci sono dati disponibili per la lettura
            ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                std::cerr << "> Connessione socket " << client_socket << " chiusa." << std::endl;
                break;
            } else if (bytes_read != PACKET_SIZE) {
                throw std::runtime_error("Formato pacchetto errato.");
                return;
            }

            Packet packet = Packet::deserialize(buffer, bytes_read);
            std::cout << "Client > " << packet.getTypeAsString() << std::endl;
            switch (packet.mType) { // pacchetti ricevuti dal client
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
                case PacketType::LOGIN_REQUEST:
                case PacketType::REGISTER_REQUEST:
                case PacketType::LOGIN_OK:
                case PacketType::REGISTER_OK:
                case PacketType::ERROR:
                case PacketType::BBS_LIST:
                    {
                        Packet answerPacket(PacketType::BBS_LIST, "Ecco la lista...");
                        std::vector<char> serialized = answerPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) < 0) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }
                    break;
                case PacketType::BBS_GET:
                case PacketType::BBS_ADD:
                default:
                    break;
            }
        }

        // il server invia SERVER_CLOSING
        Packet closingPacket(PacketType::SERVER_CLOSING);
        std::vector<char> serialized = closingPacket.serialize();
        if (write(client_socket, serialized.data(), serialized.size()) < 0) {
            std::cerr << "[!] Impossibile scrivere al client." << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    close(client_socket);
}