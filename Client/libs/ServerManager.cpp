#include "ServerManager.hpp"

// Definire i comandi come costanti intere
enum Command {
    CMD_REGISTER,
    CMD_LOGIN,
    CMD_LIST,
    CMD_GET,
    CMD_ADD,
    CMD_HELP,
    CMD_UNKNOWN
};

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

// Funzione per dividere una stringa in argomenti
std::vector<std::string> splitInput(const std::string& input) {
    std::istringstream iss(input);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

// lettura nascosta della password. Purtroppo va separata per Windows (mostra *) e Linux (non mostra l'input)
std::string readPassword() {
    std::string password;
    int illegalPassword = false;

    do {
        std::cout << (illegalPassword? "\n": "") << "Inserisci password: ";
        #ifdef _WIN32
            char ch;
            password.clear();
            while ((ch = _getch()) != '\r') {
                if (ch == '\b' && !password.empty()) {
                    std::cout << "\b \b";
                    password.pop_back();
                } else if (ch != '\b') {
                    password.push_back(ch);
                    std::cout << '*';
                }
            }
            std::cout << std::endl;
        #else
            termios oldt, newt;
            tcgetattr(STDIN_FILENO, &oldt);
            newt = oldt;
            newt.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            std::getline(std::cin, password);
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        #endif
        illegalPassword = true;
    } while (password.empty());
    std::cout << std::endl;
    return password;
}


// Funzione per validare un'email tramite regex
bool isValidEmail(const std::string& email) {
    const std::regex pattern(R"((\w+)(\.{1}\w+)*@(\w+)(\.{1}\w+)*(\.\w{2,})+)");
    return std::regex_match(email, pattern);
}

// Funzione per validare lunghezza degli argomenti
bool validateLength(const std::string& arg, size_t maxLength) {
    return arg.length() <= maxLength;
}

void handle_server(int server_socket, volatile sig_atomic_t keepRunning) {
    try {
        CryptoManager cryptoManager;

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
            throw std::runtime_error("Impossibile continuare a causa di un errore di comunicazione.");
        }

        std::string userInput;
        std::cout << "Comando: ";
        while (keepRunning && std::getline(std::cin, userInput)) {
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
                            // TODO
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

            if (userInput.length() > DATA_SIZE-1) {
                std::cout << "[!] Il messaggio supera il limite di " << (DATA_SIZE-1) << " caratteri." << std::endl;
                continue;
            }

            /* Packet otherPacket(PacketType::OTHER, userInput);
            std::vector<char> serializedOther = otherPacket.serialize();
            if (write(server_socket, serializedOther.data(), serializedOther.size()) == -1) {
                std::cerr << "[!] Errore nella scrittura sul server_socket." << std::endl;
                break;
            } */

           if(keepRunning) std::cout << "Comando: ";
        }
        std::cout << std::endl;

        close(server_socket);
    } catch (const std::exception& e) {
        std::cerr << "[!] Si è verificato un errore grave: " << e.what() << std::endl;
        exit(1);
    }
}