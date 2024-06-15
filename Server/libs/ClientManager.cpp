#include "ClientManager.hpp"

extern PersistentMemory* memory;
extern volatile std::atomic<bool> serverRunning;

void handle_client(int client_socket) {
    bool clientQuit = false;

    try {
        char buffer[PACKET_SIZE];
        
        while (serverRunning && !clientQuit) {
            memset(buffer, 0, sizeof(buffer));

            // Configura il file descriptor set per la select
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_socket, &read_fds);

            // Imposta il timeout della select
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

            // Ci sono dati disponibili per la lettura, da qui in poi
            ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                std::cerr << "> La connessione col client " << client_socket << " si è chiusa inaspettatamente." << std::endl;
                break;
            } else if (bytes_read != PACKET_SIZE) {
                throw std::runtime_error("Formato pacchetto errato.");
            }

            Packet packet = Packet::deserialize(buffer, bytes_read);
            std::cout << "Client > " << packet.getTypeAsString() << std::endl;
            switch (packet.mType) { // pacchetti inviati dal client
                case PacketType::BYE: {
                    std::cout << "> Il client " << client_socket << " si è disconnesso." << std::endl;
                    clientQuit = true;
                    break;
                }
                break;
                case PacketType::LOGIN_REQUEST: {

                }
                break;
                case PacketType::REGISTER_REQUEST: {

                }
                break;
                case PacketType::ERROR: {
                    
                }
                break;
                case PacketType::BBS_LIST: {
                    Packet answerPacket(PacketType::BBS_LIST, "Ecco la lista...");
                    std::vector<char> serialized = answerPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                }
                break;
                case PacketType::BBS_GET: {

                }
                break;
                case PacketType::BBS_ADD: {

                }
                break;
                default: {

                }
                break;
            }
        }

        // il server invia SERVER_CLOSING
        if(!serverRunning) {
            Packet closingPacket(PacketType::SERVER_CLOSING);
            std::vector<char> serialized = closingPacket.serialize();
            if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        serverRunning = false;
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    close(client_socket);
}