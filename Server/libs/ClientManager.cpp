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

    // viene riempito con il codice di verifica se l'utente si registra
    std::string clientVerificationCode = "-1";

    // per ricordarsi dell'utente autenticato
    User* currentUser = nullptr;

    // per ricordarsi se l'handshake è stato fatto
    bool isHandShakeDone = false;

    // impostato a vero quando il client si disconnette
    bool clientQuit = false;
    try {
        char buffer[MAX_PACKET_SIZE];
        
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
                if(currentUser != nullptr) { removeAuthUser(currentUser->getNickname()); isHandShakeDone = false; }
                std::cerr << "> La connessione col client " << client_socket << " si è chiusa inaspettatamente." << std::endl;
                break;
            }

            Packet packet;
            if(isHandShakeDone) {
                std::vector<char> decrypted = (*crypto).decryptSessionMessage(client_socket, buffer, bytes_read);
                packet = Packet::deserialize(decrypted.data(), decrypted.size()); // decritta
            } else {
                packet = Packet::deserialize(buffer, bytes_read);
            }
            
            //std::cout << "Client > " << packet.getTypeAsString() << std::endl;
            switch (packet.mType) { // pacchetti inviati dal client
                case PacketType::HELLO: {
                    std::cout << "> Inizializzazione comunicazione con client " << client_socket << "." << std::endl;

                    // calcolo p e g
                    std::string toSend = (*crypto).prepareDHParams();

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

                    std::string myPubKey = (*crypto).preparePublicKey(client_socket);
                    std::string myCert = (*crypto).prepareCertificate();
                    // mando chiave pubblica, certificato, firma al client
                    (*crypto).derivateK(client_socket);
                    std::string mySignature = (*crypto).prepareSignedPair(client_socket);

                    // Creazione di un oggetto JSON con i dati
                    nlohmann::json jsonData;
                    jsonData["publicKey"] = myPubKey;
                    jsonData["certificate"] = myCert;
                    jsonData["signedEncryptedPair"] = mySignature;

                    Packet answerHandshakePacket(PacketType::HANDSHAKE, jsonData.dump());
                    std::vector<char> serialized = answerHandshakePacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::HANDSHAKE_FINAL: {
                    nlohmann::json m3 = nlohmann::json::parse(packet.getContent());
                    std::string clientCertificate = m3["certificate"];
                    std::string clientSignedEncryptedPair = m3["signedEncryptedPair"];

                    (*crypto).varCheck(client_socket, clientCertificate, base64_decode(clientSignedEncryptedPair));

                    Packet answerHandshakeFinalPacket(PacketType::HANDSHAKE_FINAL);
                    std::vector<char> serialized = answerHandshakeFinalPacket.serialize();
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }

                    isHandShakeDone = true; // finito handshake
                    std::cout << "> Handshake con client " << client_socket << " terminato." << std::endl;
                    
                }
                break;
                case PacketType::BYE: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare
                    std::cout << "> Il client " << client_socket << " si è disconnesso." << std::endl;
                    clientQuit = true;
                    isHandShakeDone = false;
                    break;
                }
                break;
                case PacketType::LOGIN_REQUEST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 2) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    std::string password = tokens[1];
                    if(!toAuthenticate.checkPassword(password)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Password errata.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerLoginOKPacket.serialize());
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::REGISTER_REQUEST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 3) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }
                    email = tokens[0];
                    
                    if (!validateLength(tokens[1], 16)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato nickname errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    nickname = tokens[1];

                    password = tokens[2];

                    // simulo l'invio di una email con un codice al client e informo il client che dovrà inserire un codice
                    Packet answerRegisterCheckPacket(PacketType::REGISTER_CHECK);
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerRegisterCheckPacket.serialize());
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
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    std::string toCheck = packet.getContent();
                    if(toCheck != clientVerificationCode) {
                        Packet answerErrorPacket(PacketType::ERROR, "Codice di verifica errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }
                    
                    if(toRegister == nullptr) {
                        Packet answerErrorPacket(PacketType::ERROR, "Errore durante la procedura di verifica.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                            break;
                        }
                    }

                    memory->addUser(*toRegister);

                    Packet answerRegisterOKPacket(PacketType::REGISTER_OK);
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerRegisterOKPacket.serialize());
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }

                    clientVerificationCode = "-1";
                }
                break;
                case PacketType::LOGOUT_REQUEST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    // rimuovo l'utente dagli utenticati
                    removeAuthUser(currentUser->getNickname());
                    currentUser = nullptr;

                    // invio conferma al client
                    Packet answerLogoutOKPacket(PacketType::LOGOUT_OK);
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerLogoutOKPacket.serialize());
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
                case PacketType::BBS_LIST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 1) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }


                    std::vector<Message> obtainedMessages = memory->getMessages(n);
                    std::string toReturn;

                    if(obtainedMessages.size() == 0) {
                        toReturn = "Non ci sono messaggi in bacheca.";
                    } else {
                        toReturn = "========================================\n";
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
                    }

                    // rispondo con l'invio della lista dei messaggi in bacheca al client
                    Packet answerPacket(PacketType::BBS_LIST, toReturn);
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerPacket.serialize());
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                }
                break;
                case PacketType::BBS_GET: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    std::string uuid = packet.getContent();
                    if(!isValidUUID(uuid)) {
                        Packet answerErrorPacket(PacketType::ERROR);
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerPacket.serialize());
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                }
                break;
                case PacketType::BBS_ADD: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(currentUser != nullptr && !isUserAuthenticated(currentUser->getNickname())) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
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
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    } else if (!validateLength(title, 32)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'titolo' errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    } else if (!validateLength(body, 300)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'corpo' errato.");
                        std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerErrorPacket.serialize());
                        if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                            std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        }
                        break;
                    }

                    Message newMSG(title, author, body);
                    memory->addMessage(newMSG);

                    // rispondo con l'invio della conferma al client
                    Packet answerPacket(PacketType::BBS_ADD, newMSG.getUUID());
                    std::vector<char> serialized = (*crypto).encryptSessionMessage(client_socket, answerPacket.serialize());
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                        break;
                    }
                }
                break;
                default: {
                    Packet errorPacket(PacketType::ERROR, "Pacchetto non previsto. Che stai facendo?");
                    std::vector<char> serialized;
                    if(isHandShakeDone) {
                        serialized = (*crypto).encryptSessionMessage(client_socket, errorPacket.serialize());
                    } else {
                        serialized = errorPacket.serialize();
                    }
                    if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
                    }
                }
                break;
            }
        }

        // il server invia SERVER_CLOSING (non criptato)
        if(!serverRunning) {
            Packet closingPacket(PacketType::SERVER_CLOSING);
            std::vector<char> serialized;
            if(isHandShakeDone) {
                serialized = (*crypto).encryptSessionMessage(client_socket, closingPacket.serialize());
            } else {
                serialized = closingPacket.serialize();
            }
            if (write(client_socket, serialized.data(), serialized.size()) == -1) {
                std::cerr << "[!] Errore nella scrittura sul socket." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        serverRunning = false;
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    close(client_socket);

    isHandShakeDone = false; // client disconnesso
    if(currentUser != nullptr) removeAuthUser(currentUser->getNickname()); // utente non più nella lista degli autenticati, se lo era
    // pulizia mappe
    (*crypto).removeClientSocket(client_socket);
}