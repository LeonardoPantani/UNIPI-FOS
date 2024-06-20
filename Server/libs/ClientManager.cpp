#include "ClientManager.hpp"

// Memoria locale per i client autenticati
std::mutex authenticatedUsersMutex;
std::vector<std::string> authenticatedUsers;

void addAuthUser(const std::string& nickname) {
    std::lock_guard<std::mutex> lock(authenticatedUsersMutex);
    authenticatedUsers.push_back(nickname);
}

void removeAuthUser(const std::string& nickname) {
    std::lock_guard<std::mutex> lock(authenticatedUsersMutex);
    auto it = std::remove(authenticatedUsers.begin(), authenticatedUsers.end(), nickname);
    if (it != authenticatedUsers.end()) {
        authenticatedUsers.erase(it, authenticatedUsers.end());
    }
}

bool isUserAuthenticated(const std::string& nickname) {
    std::lock_guard<std::mutex> lock(authenticatedUsersMutex);
    return std::find(authenticatedUsers.begin(), authenticatedUsers.end(), nickname) != authenticatedUsers.end();
}

// Variabili da main
extern PersistentMemory* memory;
extern volatile std::atomic<bool> serverRunning;
extern CryptoServer* crypto;

std::string generateVerificationCode() {
    std::random_device rd; 
    std::mt19937 gen(rd()); 
    std::uniform_int_distribution<> dis(0, 9); 
    std::string result;
    for (int i = 0; i < 4; ++i) {
        int randomNumber = dis(gen);
        result += std::to_string(randomNumber);
    }
    return result;
}

// Funzione principale eseguita su un thread che gestisce un singolo client
void handle_client(int client_socket) {
    // per completare la registrazione
    User* toRegister = nullptr;
    std::string clientVerificationCode = "-1";

    // per ricordarsi dell'utente autenticato
    User* currentUser = nullptr;

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
                if(currentUser != nullptr) removeAuthUser(currentUser->getNickname());
                std::cerr << "> La connessione col client " << client_socket << " si è chiusa inaspettatamente." << std::endl;
                break;
            } else if (bytes_read != PACKET_SIZE) {
                throw std::runtime_error("Formato pacchetto errato.");
            }

            Packet packet = Packet::deserialize(buffer, bytes_read);
            std::cout << "Client > " << packet.getTypeAsString() << std::endl;
            switch (packet.mType) { // pacchetti inviati dal client
                case PacketType::HELLO: {
                    // calcolo p e g
                    std::string toSend = (*crypto).prepareDHParams();
                    std::cout << "Miei parametri p e g:" << std::endl;
                    (*crypto).printDHParameters();

                    Packet answerHelloPacket(PacketType::HELLO, toSend); // invio p e g al client
                    std::vector<char> serialized = answerHelloPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::HANDSHAKE: {
                    // ricevuta chiave pubblica dal client
                    (*crypto).receivePublicKey(client_socket, packet.getContent());
                    std::cout << "Chiave pubblica dal client:\n";
                    (*crypto).printPubKey(client_socket);

                    // mando chiave pubblica, certificato, firma al client
                    std::string myPubKey = (*crypto).preparePublicKey();
                    std::string myCert = (*crypto).prepareCertificate();
                    (*crypto).derivateK(client_socket);
                    std::cout << "Mia chiave pubblica:\n" << myPubKey << std::endl;
                    std::cout << "Mio certificato:\n" << myCert << std::endl;
                    // TODO preparare anche certificato e firma e spedire
                }
                break;
                case PacketType::BYE: {
                    std::cout << "> Il client " << client_socket << " si è disconnesso." << std::endl;
                    clientQuit = true;
                    if(currentUser != nullptr) removeAuthUser(currentUser->getNickname());
                    break;
                }
                break;
                case PacketType::LOGIN_REQUEST: {
                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 2) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                        break;
                    }
                    // da qui in poi il numero di argomenti è corretto
                    
                    std::string nickname = tokens[0];
                    if(isUserAuthenticated(nickname)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Utente già autenticato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    User toAuthenticate;
                    try {
                        toAuthenticate = memory->getUser(nickname);
                    } catch (UserNotFoundException const&) {
                        Packet answerErrorPacket(PacketType::ERROR, "Utente non trovato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    std::string password = tokens[1];
                    if(!toAuthenticate.checkPassword(password)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Password errata.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    // aggiungo l'utente a quelli autenticati
                    addAuthUser(nickname);
                    User user = memory->getUser(nickname);
                    currentUser = &user;

                    // rispondo al client che l'utente è stato autenticato
                    Packet answerLoginOKPacket(PacketType::LOGIN_OK);
                    std::vector<char> serialized = answerLoginOKPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::REGISTER_REQUEST: {
                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 3) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                        break;
                    }
                    // da qui in poi il numero di argomenti è corretto
                    std::string email;
                    std::string nickname;
                    std::string password;
                    if(!isValidEmail(tokens[0])) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato email errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }
                    email = tokens[0];
                    
                    if (!validateLength(tokens[1], 16)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato nickname errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }
                    bool userFound = true;
                    try {
                        memory->getUser(tokens[1]);
                    } catch(UserNotFoundException const&) {
                        userFound = false;
                    }
                    if(userFound) {
                        Packet answerErrorPacket(PacketType::ERROR, "Utente '" + tokens[1] + "' già registrato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    nickname = tokens[1];

                    password = tokens[2];

                    // simulo l'invio di una email con un codice al client e informo il client che dovrà inserire un codice
                    Packet answerRegisterCheckPacket(PacketType::REGISTER_CHECK);
                    std::vector<char> serialized = answerRegisterCheckPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }

                    // genero il codice di verifica del client per la registrazione
                    clientVerificationCode = generateVerificationCode();

                    // essendo una simulazione, lo stampo nella console del server
                    std::cout << "> Codice del client " << client_socket << " per la registrazione: " + clientVerificationCode << std::endl;
                    
                    // preparo l'utente per la registrazione
                    toRegister = new User(email, nickname, password);
                }
                break;
                case PacketType::REGISTER_CHECK: {
                    std::string toCheck = packet.getContent();
                    if(toCheck != clientVerificationCode) {
                        Packet answerErrorPacket(PacketType::ERROR, "Codice di verifica errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    
                    if(toRegister == nullptr) {
                        Packet answerErrorPacket(PacketType::ERROR, "Errore durante la procedura di verifica.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }

                    memory->addUser(*toRegister);

                    Packet registerOKPacket(PacketType::REGISTER_OK);
                    std::vector<char> serialized = registerOKPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }

                    clientVerificationCode = "-1";
                }
                break;
                case PacketType::LOGOUT_REQUEST: {
                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    // rimuovo l'utente dagli utenticati
                    removeAuthUser(currentUser->getNickname());
                    currentUser = nullptr;

                    // invio conferma al client
                    Packet logoutOKPacket(PacketType::LOGOUT_OK);
                    std::vector<char> serialized = logoutOKPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::ERROR: {
                    
                }
                break;
                case PacketType::BBS_LIST: {
                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 1) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    // da qui in poi il numero di argomenti è corretto

                    // controllo l'argomento naturale
                    size_t n;
                    try {
                        n = std::stoull(tokens[0]);

                        if(n == 0) throw std::runtime_error("Argomento uguale a 0.");
                    } catch (std::exception const&) {
                        Packet answerErrorPacket(PacketType::ERROR, "Argomento errato: deve essere un numero naturale diverso da 0.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    std::vector<Message> obtainedMessages = memory->getMessages(n);

                    std::string toReturn = "========================================\n";
                    if(n != 1) {
                        toReturn += "ULTIMI " + std::to_string(obtainedMessages.size()) + " MESSAGGI:";
                    } else {
                        toReturn += "ULTIMO MESSAGGIO:";
                    }
                    for(Message m : obtainedMessages) {
                        toReturn += "\n\n'" + m.getTitle() + "' di " + m.getAuthor() + ":\n";
                        toReturn += m.getBody() + "\n";
                        toReturn += "- Creato il " + m.getFormattedCreationTime() + "\n";
                        toReturn += "- UUID: " + m.getUUID();
                    }
                    toReturn += "\n========================================";

                    // rispondo con l'invio della lista dei messaggi in bacheca al client
                    Packet answerPacket(PacketType::BBS_LIST, toReturn);
                    std::vector<char> serialized = answerPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                }
                break;
                case PacketType::BBS_GET: {
                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    std::string uuid = packet.getContent();
                    if(!isValidUUID(uuid)) {
                        Packet answerErrorPacket(PacketType::ERROR);
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    Message m;
                    try {
                        m = memory->getMessage(uuid);
                    } catch(MessageNotFoundException const&) {
                        Packet answerErrorPacket(PacketType::ERROR, "Messaggio non trovato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    
                    std::string toReturn = "========================================\n";
                    toReturn += "'" + m.getTitle() + "' di " + m.getAuthor() + ":\n";
                    toReturn += m.getBody() + "\n";
                    toReturn += "- Creato il " + m.getFormattedCreationTime() + "\n";
                    toReturn += "- UUID: " + m.getUUID() + "\n";
                    toReturn += "========================================";

                    // rispondo con l'invio del messaggio della bacheca al client
                    Packet answerPacket(PacketType::BBS_GET, toReturn);
                    std::vector<char> serialized = answerPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                }
                break;
                case PacketType::BBS_ADD: {
                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    // faccio parsing della stringa json ricevuta contenente "title" "author" e "body"
                    nlohmann::json jsonData = nlohmann::json::parse(packet.getContent());
                    std::string title = jsonData["title"];
                    std::string author = jsonData["author"];
                    std::string body = jsonData["body"];

                    if (!validateLength(author, 16)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'autore' errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    } else if (!validateLength(title, 32)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'titolo' errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    } else if (!validateLength(body, 300)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'corpo' errato.");
                        std::vector<char> serialized = answerErrorPacket.serialize();
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    Message newMSG(title, author, body);
                    memory->addMessage(newMSG);

                    // rispondo con l'invio della conferma al client
                    Packet answerPacket(PacketType::BBS_ADD, newMSG.getUUID());
                    std::vector<char> serialized = answerPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
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