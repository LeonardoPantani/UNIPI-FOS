#include "ClientManager.hpp"

// memoria locale per memorizzarsi gli utenti che si sono autenticati
// essendo acceduta da più funzioni "handle_client" contemporaneamente,
// è necessario un mutex per accedervi.
std::mutex authenticatedUsersMutex;
std::vector<std::string> authenticatedUsers;

/// @brief Aggiunge un utente alla lista degli utenti autenticati
/// @param toAdd l'utente da aggiungere
void addAuthUser(const User* toAdd) {
    std::lock_guard<std::mutex> lock(authenticatedUsersMutex);
    if(toAdd != nullptr) authenticatedUsers.push_back(toAdd->getNickname());
}

/// @brief Rimuove un utente dalla lista degli utenti autenticati
/// @param toRemove l'utente da rimuovere
void removeAuthUser(const User* toRemove) {
    std::lock_guard<std::mutex> lock(authenticatedUsersMutex);
    if(toRemove != nullptr) {
        std::vector<std::string>::iterator it = std::remove(authenticatedUsers.begin(), authenticatedUsers.end(), toRemove->getNickname());
        if (it != authenticatedUsers.end()) {
            authenticatedUsers.erase(it, authenticatedUsers.end());
        }
    }
}

/// @brief Controlla se l'utente compare nella lista degli utenti autenticati
/// @param toCheck l'utente da controllare
/// @return TRUE se è autenticato, FALSE altrimenti
bool isUserAuthenticated(const User* toCheck) {
    std::lock_guard<std::mutex> lock(authenticatedUsersMutex);
    if(toCheck != nullptr)
        return std::find(authenticatedUsers.begin(), authenticatedUsers.end(), toCheck->getNickname()) != authenticatedUsers.end();
    return false;
}



void handle_client(int client_socket) {
    // contiene l'utente che sta venendo registrato
    // è modificato col pacchetto REGISTER_REQUEST (per creare l'utente) e REGISTER_CHECK (per il codice monouso)
    User* toRegister = nullptr;

    // viene riempito con il codice di verifica se l'utente si registra
    // è modificato col pacchetto REGISTER_REQUEST
    std::string clientVerificationCode = "-1";

    // contiene l'utente attualmente autenticato
    // è acceduto dai pacchetti che richiedono che l'utente sia autenticato
    // è modificato col pacchetto LOGIN_REQUEST
    // è rimosso col pacchetto LOGOUT o quando il client interrompe la connessione
    User* currentUser = nullptr;

    // viene impostato a TRUE quando l'handshake viene completato
    // è acceduto dai pacchetti che richiedono che l'handshake sia stato completato...
    // ... (tutti eccetto HELLO, HANDSHAKE, HANDSHAKE_FINAL e, a volte, SERVER_CLOSING)
    bool isHandShakeDone = false;

    // viene impostato a TRUE quando il client si è disconnesso
    // è acceduto nel ciclo while sottostante in modo di uscire quando il client si disconnette
    bool clientQuit = false;

    long nonce = 0;
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
                removeAuthUser(currentUser);
                isHandShakeDone = false;
                std::cerr << "> La connessione col client " << client_socket << " si è chiusa inaspettatamente." << std::endl;
                break;
            }

            // ricevo il pacchetto
            // se ho già fatto l'handshake, devo decrittarlo
            // se non ho fatto l'handshake, lo elaboro così com'è
            Packet packet;
            if(isHandShakeDone) {
                std::vector<char> decrypted = crypto->decryptSessionMessage(client_socket, buffer, bytes_read, &nonce);
                packet = Packet::deserialize(decrypted.data(), decrypted.size());
            } else {
                packet = Packet::deserialize(buffer, bytes_read);
            }
            
            switch (packet.mType) { // entro nel case corretto in base al pacchetto che il client mi ha mandato
                case PacketType::HELLO: {
                    std::cout << "> Inizializzazione comunicazione con client " << client_socket << "." << std::endl;

                    // preparo la stringa contenente "P G" parametri DHKE separati da spazio
                    std::string toSend = crypto->prepareDHParams();

                    Packet answerHelloPacket(PacketType::HELLO, toSend); // invio p e g al client
                    std::vector<char> serialized = answerHelloPacket.serialize();
                    WRITE(client_socket, serialized);
                }
                break;
                case PacketType::HANDSHAKE: {
                    // ricevuta chiave pubblica dal client
                    crypto->receivePublicKey(client_socket, packet.getContent());

                    std::string myPubKey = crypto->preparePublicKey(client_socket);
                    std::string myCert = crypto->prepareCertificate();
                    // mando chiave pubblica, certificato, firma al client
                    crypto->derivateK(client_socket);
                    std::string mySignature = crypto->prepareSignedPair(client_socket);

                    // Creazione di un oggetto JSON con i dati
                    nlohmann::json jsonData;
                    jsonData["publicKey"] = myPubKey;
                    jsonData["certificate"] = myCert;
                    jsonData["signedEncryptedPair"] = mySignature;

                    Packet answerHandshakePacket(PacketType::HANDSHAKE, jsonData.dump());
                    std::vector<char> serialized = answerHandshakePacket.serialize();
                    WRITE(client_socket, serialized);
                }
                break;
                case PacketType::HANDSHAKE_FINAL: {
                    nlohmann::json m3 = nlohmann::json::parse(packet.getContent());
                    std::string clientCertificate = m3["certificate"];
                    std::string clientSignedEncryptedPair = m3["signedEncryptedPair"];

                    crypto->varCheck(client_socket, clientCertificate, base64_decode(clientSignedEncryptedPair));

                    Packet answerHandshakeFinalPacket(PacketType::HANDSHAKE_FINAL);
                    std::vector<char> serialized = answerHandshakeFinalPacket.serialize();
                    WRITE(client_socket, serialized);

                    isHandShakeDone = true; // finito handshake
                    std::cout << "> Handshake con client " << client_socket << " terminato." << std::endl;
                }
                break;
                case PacketType::BYE: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare
                    std::cout << "> Il client " << client_socket << " si è disconnesso." << std::endl;
                    clientQuit = true;
                    isHandShakeDone = false;
                    nonce = 0;
                    break;
                }
                break;
                case PacketType::LOGIN_REQUEST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 2) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }
                    // da qui in poi il numero di argomenti è corretto

                    if(currentUser != nullptr) {
                        Packet answerErrorPacket(PacketType::ERROR, "Sei già autenticato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }
                    
                    std::string nickname = tokens[0];
                    User toAuthenticate;
                    try {
                        toAuthenticate = memory->getUser(nickname);
                    } catch (UserNotFoundException const&) {
                        Packet answerErrorPacket(PacketType::ERROR, "Utente non trovato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }
                    std::string password = tokens[1];
                    if(!toAuthenticate.checkPassword(password)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Password errata.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    if(isUserAuthenticated(&toAuthenticate)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Utente già autenticato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    // aggiungo l'utente a quelli autenticati
                    currentUser = new User(memory->getUser(nickname));
                    addAuthUser(currentUser);

                    // rispondo al client che l'utente è stato autenticato
                    Packet answerLoginOKPacket(PacketType::LOGIN_OK);
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerLoginOKPacket.serialize(), &nonce);
                    WRITE(client_socket, serialized);
                }
                break;
                case PacketType::REGISTER_REQUEST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 3) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }
                    // da qui in poi il numero di argomenti è corretto
                    std::string email;
                    std::string nickname;
                    std::string password;
                    if(!isValidEmail(tokens[0])) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato email errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                    }
                    email = tokens[0];
                    
                    if (!validateLength(tokens[1], 16)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato nickname errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                    }
                    bool userFound = true;
                    try {
                        memory->getUser(tokens[1]);
                    } catch(UserNotFoundException const&) {
                        userFound = false;
                    }
                    if(userFound) {
                        Packet answerErrorPacket(PacketType::ERROR, "Utente '" + tokens[1] + "' già registrato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }
                    nickname = tokens[1];

                    password = tokens[2];

                    // simulo l'invio di una email con un codice al client e informo il client che dovrà inserire un codice
                    Packet answerRegisterCheckPacket(PacketType::REGISTER_CHECK);
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerRegisterCheckPacket.serialize(), &nonce);
                    WRITEB(client_socket, serialized);

                    // genero il codice di verifica del client per la registrazione
                    clientVerificationCode = generateVerificationCode(4);

                    // essendo una simulazione, lo stampo nella console del server
                    std::cout << "> Codice del client " << client_socket << " per la registrazione: " + clientVerificationCode << std::endl;
                    
                    // preparo l'utente per la registrazione
                    toRegister = new User(email, nickname, password);
                }
                break;
                case PacketType::REGISTER_CHECK: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    std::string toCheck = packet.getContent();
                    if(clientVerificationCode != "-1" && toCheck != clientVerificationCode) {
                        Packet answerErrorPacket(PacketType::ERROR, "Codice di verifica errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }
                    
                    if(toRegister == nullptr) {
                        Packet answerErrorPacket(PacketType::ERROR, "Errore durante la procedura di verifica.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITEB(client_socket, serialized);
                    }

                    memory->addUser(*toRegister);

                    Packet answerRegisterOKPacket(PacketType::REGISTER_OK);
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerRegisterOKPacket.serialize(), &nonce);
                    WRITE(client_socket, serialized);

                    clientVerificationCode = "-1";
                }
                break;
                case PacketType::LOGOUT_REQUEST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(!isUserAuthenticated(currentUser)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    // rimuovo l'utente dagli utenticati
                    removeAuthUser(currentUser);
                    currentUser = nullptr;

                    // invio conferma al client
                    Packet answerLogoutOKPacket(PacketType::LOGOUT_OK);
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerLogoutOKPacket.serialize(), &nonce);
                    WRITE(client_socket, serialized);
                }
                break;
                case PacketType::BBS_LIST: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(!isUserAuthenticated(currentUser)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    std::vector<std::string> tokens = splitInput(packet.getContent());
                    if(tokens.size() != 1) { // numero di argomenti errato
                        Packet answerErrorPacket(PacketType::ERROR, "Numero di argomenti errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
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
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
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
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerPacket.serialize(), &nonce);
                    WRITE(client_socket, serialized);
                }
                break;
                case PacketType::BBS_GET: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(!isUserAuthenticated(currentUser)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    std::string uuid = packet.getContent();
                    if(!isValidUUID(uuid)) {
                        Packet answerErrorPacket(PacketType::ERROR);
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    Message m;
                    try {
                        m = memory->getMessage(uuid);
                    } catch(MessageNotFoundException const&) {
                        Packet answerErrorPacket(PacketType::ERROR, "Messaggio non trovato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
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
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerPacket.serialize(), &nonce);
                    WRITE(client_socket, serialized);
                }
                break;
                case PacketType::BBS_ADD: {
                    if(!isHandShakeDone) { clientQuit = true; break; } // se l'handshake non è stato completato questo pacchetto non dovrebbe mai arrivare

                    if(!isUserAuthenticated(currentUser)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Non sei autenticato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    // faccio parsing della stringa json ricevuta contenente "title" "author" e "body"
                    nlohmann::json jsonData = nlohmann::json::parse(packet.getContent());
                    std::string title = jsonData["title"];
                    std::string author = jsonData["author"];
                    std::string body = jsonData["body"];

                    if (!validateLength(author, 16)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'autore' errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    } else if (!validateLength(title, 32)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'titolo' errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    } else if (!validateLength(body, 300)) {
                        Packet answerErrorPacket(PacketType::ERROR, "Formato campo 'corpo' errato.");
                        std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerErrorPacket.serialize(), &nonce);
                        WRITE(client_socket, serialized);
                        break;
                    }

                    Message newMSG(title, author, body);
                    memory->addMessage(newMSG);

                    // rispondo con l'invio della conferma al client
                    Packet answerPacket(PacketType::BBS_ADD, newMSG.getUUID());
                    std::vector<char> serialized = crypto->encryptSessionMessage(client_socket, answerPacket.serialize(), &nonce);
                    WRITE(client_socket, serialized);
                }
                break;
                default: {
                    Packet errorPacket(PacketType::ERROR, "Pacchetto non previsto. Che stai facendo?");
                    std::vector<char> serialized;
                    if(isHandShakeDone)
                        serialized = crypto->encryptSessionMessage(client_socket, errorPacket.serialize(), &nonce);
                    else
                        serialized = errorPacket.serialize();
                    WRITE(client_socket, serialized);
                }
                break;
            }
        }

        // il server invia SERVER_CLOSING
        if(!serverRunning) {
            Packet closingPacket(PacketType::SERVER_CLOSING);
            std::vector<char> serialized;
            if(isHandShakeDone)
                serialized = crypto->encryptSessionMessage(client_socket, closingPacket.serialize(), &nonce);
            else
                serialized = closingPacket.serialize();
            WRITE(client_socket, serialized);
        }
    } catch (const std::exception& e) {
        serverRunning = false;
        std::cerr << "[!] Errore: " << e.what() << std::endl;
    }
    close(client_socket);
    --activeConnections; // decremento connessioni attive
    isHandShakeDone = false; // client disconnesso
    nonce = 0;
    removeAuthUser(currentUser); // utente non più nella lista degli autenticati, se lo era
    currentUser = nullptr;
    crypto->removeClientSocket(client_socket);
}