#include "ServerManager.hpp"

bool isVerificationCodeRequired = false;
bool amIAuthenticated = false;
extern CryptoClient* crypto;

// Funzione per ottenere il comando dal testo inserito
Command getCommand(const std::string& command) {
    static const std::map<std::string, Command> commandMap = {
        {"register", CMD_REGISTER},
        {"login", CMD_LOGIN},
        {"logout", CMD_LOGOUT},
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

// Ottenimento corretto dell'input per il comando ADD
std::tuple<std::string, std::string, std::string> addMessageCommandParser(const std::string& input) {
    std::istringstream iss(input);
    std::string command, part1, part2, part3;
    char quote;
    iss >> command;
    if (!(iss >> quote) || quote != '"') {
        throw std::invalid_argument("");
    }
    std::getline(iss, part1, '"');
    if (!(iss >> quote) || quote != '"') {
        throw std::invalid_argument("");
    }
    std::getline(iss, part2, '"');
    if (!(iss >> quote) || quote != '"') {
        throw std::invalid_argument("");
    }
    std::getline(iss, part3, '"');
    if (iss >> std::ws && !iss.eof()) {
        throw std::invalid_argument("");
    }

    return std::make_tuple(part1, part2, part3);
}

void handle_server(int server_socket, volatile sig_atomic_t &clientRunning) {
    bool serverClosing = false;

    try {
        char buffer[PACKET_SIZE];

        // invio pacchetto HELLO iniziale al server con corpo
        Packet firstHelloPacket(PacketType::HELLO);
        std::vector<char> serializedHello = firstHelloPacket.serialize();
        if(write(server_socket, serializedHello.data(), serializedHello.size()) == -1) {
            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
            throw std::runtime_error("Impossibile inviare HELLO al server.");
        }

        while(clientRunning && !serverClosing) {
            memset(buffer, 0, sizeof(buffer));

            // configuro file descriptor set per la select
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_socket, &read_fds);

            // imposta il timeout della select
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            // chiamo select per vedere se ci sono dati pronti per la lettura
            int select_result = select(server_socket + 1, &read_fds, NULL, NULL, &timeout);
            if (select_result <= 0) { // se eseguo CTRL+C (o non c'è niente da leggere), questo branch è eseguito
                continue;
            }

            // ci sono dati disponibili per la lettura, da qui in poi
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
                    // ho ricevuto i parametri g e p
                    (*crypto).receiveDHParameters(packet.getContent());

                    // mando chiave pubblica al server
                    std::string myPubKey = (*crypto).preparePublicKey();
                    Packet handshakePacket(PacketType::HANDSHAKE, myPubKey);
                    std::vector<char> serializedBye = handshakePacket.serialize();
                    if (write(server_socket, serializedBye.data(), serializedBye.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::HANDSHAKE: {
                    // ho ricevuto M2 dal server
                    nlohmann::json jsonData = nlohmann::json::parse(packet.getContent());
                    std::string serverPublicKey = jsonData["publicKey"];
                    std::string serverCertificate = jsonData["certificate"];
                    std::string serverSignedEncryptedPair = jsonData["signedEncryptedPair"];

                    (*crypto).receivePublicKey(serverPublicKey); // g^b
                    (*crypto).derivateK();

                    // controllo pacchetto del server
                    (*crypto).varCheck(serverCertificate, base64_decode(serverSignedEncryptedPair));

                    std::string mySignature = (*crypto).prepareSignedPair();
                    std::string myCert = (*crypto).prepareCertificate();
                    nlohmann::json m3;
                    m3["signedEncryptedPair"] = mySignature;
                    m3["certificate"] = myCert;

                    Packet handshakeFinalPacket(PacketType::HANDSHAKE_FINAL, m3.dump());
                    std::vector<char> serializedBye = handshakeFinalPacket.serialize();
                    if (write(server_socket, serializedBye.data(), serializedBye.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::HANDSHAKE_FINAL: {
                    
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
                    amIAuthenticated = true;
                }
                break;
                case PacketType::REGISTER_CHECK: {
                    std::cout << "> Il server richiede un codice di verifica per la registrazione. Inseriscilo." << std::endl;
                    isVerificationCodeRequired = true;
                }
                break;
                case PacketType::REGISTER_OK: {
                    isVerificationCodeRequired = false;
                }
                break;
                case PacketType::LOGOUT_OK: {
                    amIAuthenticated = false;
                }
                break;
                case PacketType::ERROR: {
                    std::cerr << "Server > [!] " << packet.getContent() << std::endl;
                }
                break;
                case PacketType::BBS_LIST: {
                    std::cout << packet.getContent() << std::endl;
                }
                break;
                case PacketType::BBS_GET: {
                    std::cout << packet.getContent() << std::endl;
                }
                break;
                case PacketType::BBS_ADD: {
                    std::cout << "> Messaggio aggiunto in bacheca con l'UUID: " << packet.getContent() << std::endl;
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
            std::vector<char> serializedBye = byePacket.serialize();
            if (write(server_socket, serializedBye.data(), serializedBye.size()) == -1) {
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
        Command cmd = getCommand(tokens[0]);

        switch (cmd) {
            case CMD_REGISTER: {
                if(amIAuthenticated) {
                    std::cerr << "[!] Sei già autenticato. Esegui il logout prima di poter effettuare un'altra registrazione." << std::endl;
                    break;
                }

                if (tokens.size() != 4) {
                    std::cout << "[!] Uso corretto: register <email> <nickname> <password>" << std::endl;
                    break;
                }

                std::string email;
                if (!isValidEmail(tokens[1])) {
                    std::cout << "[!] Email non valida." << std::endl;
                    break;
                }
                email = tokens[1];

                std::string nickname;
                if (!validateLength(tokens[2], 16)) {
                    std::cout << "[!] Il nickname non può superare i 16 caratteri." << std::endl;
                    break;
                }
                nickname = tokens[2];

                std::string password = tokens[3];

                // invio pacchetto REGISTER_REQUEST con corpo: email nickname password
                Packet registerPacket(PacketType::REGISTER_REQUEST, (email + " " + nickname + " " + password));
                std::vector<char> serializedLogin = registerPacket.serialize();
                if(write(server_socket, serializedLogin.data(), serializedLogin.size()) == -1) {
                    std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                }
            }
            break;
            case CMD_LOGIN: {
                if (tokens.size() != 3) {
                    std::cout << "[!] Uso corretto: login <nickname> <password>" << std::endl;
                    break;
                }

                std::string nickname;
                if (!validateLength(tokens[1], 16)) {
                    std::cout << "[!] Il nickname non può superare i 16 caratteri." << std::endl;
                    break;
                }
                nickname = tokens[1];

                std::string password = tokens[2];

                // invio pacchetto LOGIN_REQUEST con corpo: nickname password
                Packet loginPacket(PacketType::LOGIN_REQUEST, (nickname + " " + password));
                std::vector<char> serializedLogin = loginPacket.serialize();
                if(write(server_socket, serializedLogin.data(), serializedLogin.size()) == -1) {
                    std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                }
            }
            break;
            case CMD_LOGOUT: {
                if(!amIAuthenticated) {
                    std::cerr << "[!] Non sei autenticato." << std::endl;
                    break;
                }

                // invio pacchetto LOGOUT_REQUEST
                Packet logoutPacket(PacketType::LOGOUT_REQUEST);
                std::vector<char> serializedLogin = logoutPacket.serialize();
                if(write(server_socket, serializedLogin.data(), serializedLogin.size()) == -1) {
                    std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                }
            }
            break;
            case CMD_LIST: {
                if(!amIAuthenticated) {
                    std::cerr << "[!] Non sei autenticato." << std::endl;
                    break;
                }

                if (tokens.size() != 2) {
                    std::cout << "[!] Uso corretto: list <n>" << std::endl;
                    break;
                }

                try {
                    try {
                        if (std::stoi(tokens[1]) <= 0) throw;
                    } catch(std::exception const&e) {
                        throw;
                    }
                    // invio pacchetto BBS_LIST
                    Packet packet(PacketType::BBS_LIST, tokens[1]);
                    std::vector<char> serialized = packet.serialize();
                    if (write(server_socket, serialized.data(), serialized.size()) < 0) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                } catch (std::exception&) {
                    std::cout << "[!] Argomento non valido." << std::endl;
                }
            }
            break;
            case CMD_GET: {
                if(!amIAuthenticated) {
                    std::cerr << "[!] Non sei autenticato." << std::endl;
                    break;
                }

                if (tokens.size() != 2) {
                    std::cerr << "[!] Uso corretto: get <message_UUID>" << std::endl;
                    break;
                }

                if(!isValidUUID(tokens[1])) {
                    std::cerr << "[!] Uso corretto: get <message_UUID>" << std::endl;
                    break;
                }
                std::string uuid = tokens[1];

                // invio pacchetto BBS_GET
                Packet packet(PacketType::BBS_GET, uuid);
                std::vector<char> serialized = packet.serialize();
                if (write(server_socket, serialized.data(), serialized.size()) < 0) {
                    std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    break;
                }
            }
            break;
            case CMD_ADD: {
                if(!amIAuthenticated) {
                    std::cerr << "[!] Non sei autenticato." << std::endl;
                    break;
                }

                std::string title, author, body;
                try {
                    std::tie(title, author, body) = addMessageCommandParser(userInput);
                } catch(std::invalid_argument const&) {
                    std::cerr << "[!] Uso corretto: add \"title\" \"author\" \"body\"" << std::endl;
                    break;
                }
                
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

                // Creazione di un oggetto JSON con i dati
                nlohmann::json jsonData;
                jsonData["title"] = title;
                jsonData["author"] = author;
                jsonData["body"] = body;
                std::string jsonStr = jsonData.dump();
                
                // invio pacchetto BBS_ADD
                Packet packet(PacketType::BBS_ADD, jsonStr);
                std::vector<char> serialized = packet.serialize();
                if (write(server_socket, serialized.data(), serialized.size()) < 0) {
                    std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    break;
                }
            }
            break;
            case CMD_HELP: {
                std::cout << "Comandi disponibili:" << std::endl;
                std::cout << "| register <email> <nickname> <password> - Registrazione utente" << std::endl;
                std::cout << "| login <nickname> <password> - Autenticazione utente" << std::endl;
                std::cout << "| list [n] - Mostra gli ultimi n messaggi" << std::endl;
                std::cout << "| get <messageid> - Ottieni il messaggio con ID specificato" << std::endl;
                std::cout << "| add <title> <author> <body> - Aggiungi un nuovo messaggio" << std::endl;
                std::cout << "| help - Mostra questo messaggio di aiuto" << std::endl;
            }
            break;
            case CMD_UNKNOWN: { // inserimento codice di verifica
                if(!isVerificationCodeRequired) { std::cout << "[!] Comando errato. Scrivi 'help' per una lista di comandi." << std::endl; break; }
                
                std::string verificationCode = tokens[0];
                // invio il codice di verifica
                Packet verificationCodePacket(PacketType::REGISTER_CHECK, verificationCode);
                std::vector<char> serializedLogin = verificationCodePacket.serialize();
                if(write(server_socket, serializedLogin.data(), serializedLogin.size()) == -1) {
                    std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                }
            }
            break;
            default:
                break;
        }
    }
}