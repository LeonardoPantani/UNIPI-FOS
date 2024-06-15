#include "ServerManager.hpp"

// Funzione per ottenere il comando dal testo inserito
Command getCommand(const std::string& command) {
    static const std::map<std::string, Command> commandMap = {
        {"register", CMD_REGISTER},
        {"login", CMD_LOGIN},
        {"list", CMD_LIST},
        {"get", CMD_GET},
        {"add", CMD_ADD},
        {"help", CMD_HELP}
    };

    auto it = commandMap.find(command);
    if (it != commandMap.end()) {
        return it->second;
    } else {
        return CMD_UNKNOWN;
    }
}

void handle_server(int server_socket, volatile sig_atomic_t &clientRunning) {
    bool serverClosing = false;

    try {
        char buffer[PACKET_SIZE];

        while(clientRunning && !serverClosing) {
            memset(buffer, 0, sizeof(buffer));

            // Configura il file descriptor set per la select
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_socket, &read_fds);

            // Imposta il timeout della select
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            // Chiama select per vedere se ci sono dati pronti per la lettura
            int select_result = select(server_socket + 1, &read_fds, NULL, NULL, &timeout);
            if (select_result <= 0) { // se eseguo CTRL+C (o non c'è niente da leggere), questo branch è eseguito
                continue;
            }

            // Ci sono dati disponibili per la lettura, da qui in poi
            ssize_t bytes_read = read(server_socket, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                std::cerr << "> La connessione col server si è chiusa inaspettatamente." << std::endl;
                break;
            } else if (bytes_read != PACKET_SIZE) {
                throw std::runtime_error("Formato pacchetto errato.");
            }

            Packet packet = Packet::deserialize(buffer, bytes_read);
            std::cout << "Server > " << packet.getTypeAsString() << std::endl;

            switch (packet.mType) { // pacchetti inviati dal server
                case PacketType::HELLO: {
                    Packet helloPacket(PacketType::HELLO);
                    std::vector<char> serializedHello = helloPacket.serialize();
                    if(write(server_socket, serializedHello.data(), serializedHello.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::SERVER_FULL: {
                    clientRunning = false;
                    throw std::runtime_error("Il server non accetta ulteriori client al momento.");
                }
                break;
                case PacketType::SERVER_CLOSING: {
                    clientRunning = false;
                    serverClosing = true;
                }
                break;
                case PacketType::LOGIN_OK: {

                }
                break;
                case PacketType::REGISTER_OK: {

                }
                break;
                case PacketType::ERROR: {

                }
                break;
                case PacketType::BBS_LIST: {

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

        // se il server sta chiudendo ignorerà i BYE, altrimenti lo invio
        if(!serverClosing) {
            Packet byePacket(PacketType::BYE);
            std::vector<char> serializedHello = byePacket.serialize();
            if (write(server_socket, serializedHello.data(), serializedHello.size()) == -1) {
                std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        clientRunning = false;
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    close(server_socket);
}

void handle_user_input(int server_socket, volatile sig_atomic_t &clientRunning) {
    AsyncInput asyncIn;
    std::string userInput;

    while (clientRunning) {
        userInput = asyncIn.getLine();
        if (userInput.empty()) continue;

        std::vector<std::string> tokens = splitInput(userInput);
        if (tokens.empty()) {
            std::cout << "[!] Inserisci un comando." << std::endl;
            continue;
        }

        Command cmd = getCommand(tokens[0]);

        switch (cmd) {
            case CMD_REGISTER:
                if (tokens.size() < 3) {
                    std::cout << "[!] Uso corretto: register <email> <nickname>" << std::endl;
                } else {
                    std::string email = tokens[1];
                    std::string nickname = tokens[2];
                    if (!isValidEmail(email)) {
                        std::cout << "[!] Email non valida." << std::endl;
                        break;
                    }
                    std::string password = readPassword();
                    // TODO
                }
                break;

            case CMD_LOGIN:
                if (tokens.size() < 2) {
                    std::cout << "[!] Uso corretto: login <nickname>" << std::endl;
                } else {
                    std::string nickname = tokens[1];
                    if (!validateLength(nickname, 16)) {
                        std::cout << "[!] Il nickname non può superare i 16 caratteri." << std::endl;
                    }
                    std::string password = readPassword();
                    // TODO
                }
                break;

            case CMD_LIST:
                if (tokens.size() < 2) {
                    std::cout << "[!] Uso corretto: list <n>" << std::endl;
                } else {
                    try {
                        int n = std::stoi(tokens[1]);
                        if (n <= 0) throw std::invalid_argument("non positivo");
                        // invio pacchetto BBS_LIST
                        Packet packet(PacketType::BBS_LIST);
                        std::vector<char> serialized = packet.serialize();
                        if (write(server_socket, serialized.data(), serialized.size()) < 0) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    } catch (std::invalid_argument&) {
                        std::cout << "[!] Argomento non valido. Deve essere un intero positivo." << std::endl;
                    }
                }
                break;

            case CMD_GET:
                if (tokens.size() < 2) {
                    std::cout << "[!] Uso corretto: get <messageid>" << std::endl;
                } else {
                    try {
                        int messageId = std::stoi(tokens[1]);
                        if (messageId <= 0) throw std::invalid_argument("non positivo");
                        // TODO
                    } catch (std::invalid_argument&) {
                        std::cout << "[!] Argomento non valido per get. Deve essere un intero positivo." << std::endl;
                    }
                }
                break;

            case CMD_ADD:
                if (tokens.size() < 4) {
                    std::cout << "[!] Uso corretto: add <title> <author> <body>" << std::endl;
                } else {
                    std::string title = tokens[1];
                    std::string author = tokens[2];
                    std::string body = tokens[3];
                    if (!validateLength(author, 16)) {
                        std::cout << "[!] Il nome dell'autore non può superare i 16 caratteri." << std::endl;
                        break;
                    } else if (!validateLength(title, 32)) {
                        std::cout << "[!] Il titolo non può superare i 32 caratteri." << std::endl;
                        break;
                    } else if (!validateLength(body, 300)) {
                        std::cout << "[!] Il corpo del messaggio non può superare i 300 caratteri." << std::endl;
                        break;
                    } 
                    // TODO
                }
                break;

            case CMD_HELP:
                std::cout << "Comandi disponibili:" << std::endl;
                std::cout << "| register <email> <nickname> - Registrati con email e nickname" << std::endl;
                std::cout << "| login <nickname> - Effettua il login con il tuo nickname" << std::endl;
                std::cout << "| list [n] - Mostra gli ultimi n messaggi (opzionale)" << std::endl;
                std::cout << "| get <messageid> - Ottieni il messaggio con ID specificato" << std::endl;
                std::cout << "| add <title> <author> <body> - Aggiungi un nuovo messaggio" << std::endl;
                std::cout << "| help - Mostra questo messaggio di aiuto" << std::endl;
                break;

            default:
                std::cout << "[!] Comando errato. Scrivi 'help' per una lista di comandi." << std::endl;
                break;
        }
    }
}