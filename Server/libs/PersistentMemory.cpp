#include "PersistentMemory.hpp"

PersistentMemory::PersistentMemory(const std::string& filePath, const std::string& keyFilePath)  : filePath(filePath), keyFilePath(keyFilePath) {
    if (!loadKey()) {
        std::ifstream file(filePath);
        if (file.is_open()) { // no chiave ma sì memoria (problema)
            throw std::runtime_error("Impossibile decriptare la memoria persistente in assenza della chiave al percorso '" + keyFilePath + "'. Ripristina la chiave oppure elimina la memoria persistente al percorso '" + filePath + "' e ri-esegui questo programma per continuare.");
        } else { // nè chiave nè memoria (creo da zero)
            //std::cout << "Chiave e memoria persistente creati." << std::endl;
        }
    } else {
        if (!loadFromFile()) { // sì chiave ma no memoria
           throw std::runtime_error("Memoria persistente non trovata al percorso '" + filePath + "' ma chiave presente. Ripristina la memoria persistente oppure elimina la chiave al percorso '" + keyFilePath + "' e ri-esegui questo programma per continuare.");
        } else { // sì chiave e memoria
            //std::cout << "Lettura dalla memoria persistente completata." << std::endl;
        }
    }
}

PersistentMemory::~PersistentMemory() {
    saveToFile();
}

bool PersistentMemory::loadKey() {
    std::ifstream keyFile(keyFilePath, std::ios::binary);
    if (keyFile.is_open()) {
        keyFile.read(reinterpret_cast<char*>(key), sizeof(key));
        keyFile.read(reinterpret_cast<char*>(iv), sizeof(iv));
        keyFile.close();
        return true; // la chiave già c'era
    } else {
        std::ifstream file(filePath, std::ios::binary);
        if(file.is_open()) { file.close(); return false; } // la chiave non c'è ma la memoria persistente sì, non creo la nuova chiave per far comparire il messaggio di avviso all'utente

        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));
        saveKey();
        return false; // la chiave è stata creata
    }
}

void PersistentMemory::saveKey() {
    std::ofstream keyFile(keyFilePath, std::ios::binary);
    if (!keyFile.is_open()) {
        throw std::runtime_error("Impossibile aprire il file chiave in scrittura.");
    }
    keyFile.write(reinterpret_cast<const char*>(key), sizeof(key));
    keyFile.write(reinterpret_cast<const char*>(iv), sizeof(iv));
    keyFile.close();
}

bool PersistentMemory::loadFromFile() {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false; // memoria persistente non presente
    }

    std::string encryptedData((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    file.close();

    if (!encryptedData.empty()) {
        std::string jsonStr = decrypt(encryptedData);
        auto jsonData = nlohmann::json::parse(jsonStr);

        for (const auto& userJson : jsonData["users"]) {
            User user(
                userJson["email"], 
                userJson["nickname"], 
                userJson["password"].get<std::vector<uint8_t>>()
            );
            userMap[user.getNickname()] = user;
        }

        for (const auto& messageJson : jsonData["messages"]) {
            Message message(
                messageJson["title"], 
                messageJson["author"], 
                messageJson["body"]
            );
            messageMap[message.getUUID()] = message;
        }
        return true; // memoria persistente ok
    }

    return false; // memoria persistente vuota
}

void PersistentMemory::saveToFile() {
    nlohmann::json jsonData;
    for (const auto& pair : userMap) {
        const auto& user = pair.second;
        jsonData["users"].push_back({
            {"email", user.getEmail()},
            {"nickname", user.getNickname()},
            {"password", user.getPassword()},
            {"creationTime", user.getCreationTime()}
        });
    }

    for (const auto& pair : messageMap) {
        const auto& message = pair.second;
        jsonData["messages"].push_back({
            {"uuid", message.getUUID()},
            {"title", message.getTitle()},
            {"author", message.getAuthor()},
            {"body", message.getBody()},
            {"creationTime", message.getCreationTime()}
        });
    }

    std::string jsonStr = jsonData.dump();
    std::string encryptedData = encrypt(jsonStr);

    std::ofstream file(filePath, std::ios::trunc);
    file << encryptedData;
    file.close();
}

std::string PersistentMemory::encrypt(const std::string& plainText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Inizializzazione contesto di cifratura fallita.");

    int len;
    int cipherTextLen;
    std::string cipherText(plainText.size() + 128, '\0');

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        throw std::runtime_error("Inizializzazione cifratura fallita.");

    if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&cipherText[0]), &len, 
                               reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size()))
        throw std::runtime_error("Aggiornamento cifratura fallito.");
    cipherTextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&cipherText[0]) + len, &len))
        throw std::runtime_error("Finalizzazione cifratura fallita.");
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return cipherText.substr(0, cipherTextLen);
}

std::string PersistentMemory::decrypt(const std::string& cipherText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Inizializzazione contesto di decifratura fallita.");

    int len;
    int plainTextLen;
    std::string plainText(cipherText.size(), '\0');

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        throw std::runtime_error("Inizializzazione decifratura fallita.");

    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plainText[0]), &len, 
                               reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size()))
        throw std::runtime_error("Aggiornamento decifratura fallito.");
    plainTextLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plainText[0]) + len, &len))
        throw std::runtime_error("La decifrazione della memoria persistente è fallita: la chiave potrebbe essere errata. Impossibile proseguire.");
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return plainText.substr(0, plainTextLen);
}

void PersistentMemory::addUser(const User& user) {
    userMap[user.getNickname()] = user;
    saveToFile();
}

void PersistentMemory::addMessage(const Message& message) {
    messageMap[message.getUUID()] = message;
    saveToFile();
}

std::vector<User> PersistentMemory::getUsers() {
    std::vector<User> users;
    for (const auto& pair : userMap) {
        users.push_back(pair.second);
    }
    return users;
}

std::vector<Message> PersistentMemory::getMessages() {
    std::vector<Message> messages;
    for (const auto& pair : messageMap) {
        messages.push_back(pair.second);
    }
    return messages;
}

User PersistentMemory::getUser(const std::string& nickname) {
    auto it = userMap.find(nickname);
    if (it != userMap.end()) {
        return it->second;
    }
    throw UserNotFoundException();
}

Message PersistentMemory::getMessage(const std::string& uuid) {
    auto it = messageMap.find(uuid);
    if (it != messageMap.end()) {
        return it->second;
    }
    throw MessageNotFoundException();
}

void PersistentMemory::removeUser(const std::string& nickname) {
    userMap.erase(nickname);
    saveToFile();
}

void PersistentMemory::removeMessage(const std::string& uuid) {
    messageMap.erase(uuid);
    saveToFile();
}
