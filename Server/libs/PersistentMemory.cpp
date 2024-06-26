#include "PersistentMemory.hpp"

PersistentMemory::PersistentMemory(const std::string& dataFilePath, const std::string& keyFilePath)  : mDataFilePath(dataFilePath), mKeyFilePath(keyFilePath) {
    if (!loadKey()) {
        std::ifstream file(dataFilePath);
        if (file.is_open()) { // no chiave ma sì memoria (problema)
            throw std::runtime_error("Impossibile decriptare la memoria persistente in assenza della chiave al percorso '" + keyFilePath + "'. Ripristina la chiave oppure elimina la memoria persistente al percorso '" + dataFilePath + "' e ri-esegui questo programma per continuare.");
        } else { // nè chiave nè memoria (creo da zero)
            //std::cout << "Chiave e memoria persistente creati." << std::endl;
        }
    } else {
        if (!loadFromFile()) { // sì chiave ma no memoria
           throw std::runtime_error("Memoria persistente non trovata al percorso '" + dataFilePath + "' ma chiave presente. Ripristina la memoria persistente oppure elimina la chiave al percorso '" + keyFilePath + "' e ri-esegui questo programma per continuare.");
        } else { // sì chiave e memoria
            //std::cout << "Lettura dalla memoria persistente completata." << std::endl;
        }
    }
}

PersistentMemory::~PersistentMemory() {
    saveToFile();
}

bool PersistentMemory::loadKey() { // il file della chiave contiene: chiave (primi 32 byte, 256 bit) + IV (ultimi 16 byte, 128 bit)
    std::ifstream keyFile(mKeyFilePath, std::ios::binary);
    if (keyFile.is_open()) {
        keyFile.read(reinterpret_cast<char*>(mKey), sizeof(mKey));
        keyFile.read(reinterpret_cast<char*>(mIV), sizeof(mIV));
        keyFile.close();
        return true; // la chiave già c'era
    } else {
        std::ifstream file(mDataFilePath, std::ios::binary);
        if(file.is_open()) { file.close(); return false; } // la chiave non c'è ma la memoria persistente sì, non creo la nuova chiave per far comparire il messaggio di avviso all'utente
        RAND_bytes(mKey, sizeof(mKey));
        RAND_bytes(mIV, sizeof(mIV));
        saveKey();
        return false; // la chiave è stata creata
    }
}

void PersistentMemory::saveKey() { // il file della chiave contiene: chiave (primi 32 byte, 256 bit) + IV (ultimi 16 byte, 128 bit)
    std::ofstream keyFile(mKeyFilePath, std::ios::binary);
    if (!keyFile.is_open()) {
        throw std::runtime_error("Impossibile aprire il file chiave in scrittura.");
    }
    keyFile.write(reinterpret_cast<const char*>(mKey), sizeof(mKey));
    keyFile.write(reinterpret_cast<const char*>(mIV), sizeof(mIV));
    keyFile.close();
}

bool PersistentMemory::loadFromFile() {
    std::ifstream file(mDataFilePath);
    if (!file.is_open()) {
        return false; // memoria persistente non presente
    }

    std::string encryptedData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (!encryptedData.empty()) {
        std::string jsonStr = decrypt(encryptedData);
        auto jsonData = nlohmann::json::parse(jsonStr);

        for (const auto& userJson : jsonData["users"]) {
            User user(
                userJson["email"], 
                userJson["nickname"], 
                userJson["password"].get<std::vector<uint8_t>>(),
                userJson["salt"].get<std::vector<uint8_t>>(),
                userJson["creationTime"]
            );
            mUserMap[user.getNickname()] = user;
        }

        for (const auto& messageJson : jsonData["messages"]) {
            Message message(
                messageJson["uuid"],
                messageJson["title"], 
                messageJson["author"], 
                messageJson["body"],
                messageJson["creationTime"]
            );
            mMessageMap[message.getUUID()] = message;
        }
        return true; // memoria persistente ok
    }

    return false; // memoria persistente vuota
}

void PersistentMemory::saveToFile() {
    nlohmann::json jsonData;

    jsonData["users"] = nlohmann::json::array();
    jsonData["messages"] = nlohmann::json::array();

    for (const auto& pair : mUserMap) {
        const auto& user = pair.second;
        jsonData["users"].push_back({
            {"email", user.getEmail()},
            {"nickname", user.getNickname()},
            {"password", user.getPassword()},
            {"salt", user.getSalt()},
            {"creationTime", user.getCreationTime()}
        });
    }

    for (const auto& pair : mMessageMap) {
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

    std::ofstream file(mDataFilePath, std::ios::trunc);
    file << encryptedData;
    file.close();
}

std::string PersistentMemory::encrypt(const std::string& plainText) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Inizializzazione contesto di cifratura fallita.");

    int len;
    int cipherTextLen;
    std::string cipherText(plainText.size() + static_cast<size_t>(EVP_CIPHER_block_size(EVP_aes_256_cbc())), '\0');

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, mKey, mIV))
        throw std::runtime_error("Inizializzazione cifratura fallita.");

    if (1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&cipherText[0]), &len, 
                               reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.size()))
        throw std::runtime_error("Aggiornamento cifratura fallito.");
    cipherTextLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&cipherText[0]) + len, &len))
        throw std::runtime_error("Finalizzazione cifratura fallita.");
    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    cipherText.resize(static_cast<size_t>(cipherTextLen));

    // genero un HMAC per integrità
    std::string hmac = generateHMAC(mKey, cipherText);

    // aggiungo HMAC al testo cifrato
    cipherText += hmac;

    return cipherText;
}

std::string PersistentMemory::decrypt(const std::string& cipherText) {
    if (cipherText.size() < SHA256_DIGEST_LENGTH) {
        throw std::runtime_error("Testo cifrato troppo corto per contenere un HMAC valido.");
    }

    // estraggo dal fondo del file gli ultimi 32 byte (256 bit) che contengono l'HMAC, il resto è il testo cifrato effettivo
    std::string receivedHMAC = cipherText.substr(cipherText.size() - SHA256_DIGEST_LENGTH);
    std::string actualCipherText = cipherText.substr(0, cipherText.size() - SHA256_DIGEST_LENGTH);

    // verifico l'HMAC
    if (!verifyHMAC(mKey, actualCipherText, receivedHMAC)) {
        throw std::runtime_error("Verifica HMAC fallita: la chiave o la memoria persistente sono stati alterati.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Inizializzazione contesto di decifratura fallita.");

    int len;
    int plainTextLen;
    std::string plainText(actualCipherText.size(), '\0');

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, mKey, mIV))
        throw std::runtime_error("Inizializzazione decifratura fallita.");

    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plainText[0]), &len, 
                               reinterpret_cast<const unsigned char*>(actualCipherText.c_str()), actualCipherText.size()))
        throw std::runtime_error("Aggiornamento decifratura fallito.");
    plainTextLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plainText[0]) + len, &len))
        throw std::runtime_error("La decifrazione della memoria persistente è fallita: la chiave potrebbe essere errata. Impossibile proseguire.");
    plainTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    return plainText.substr(0, static_cast<size_t>(plainTextLen));
}

std::string PersistentMemory::generateHMAC(const unsigned char* key, const std::string& data) {
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLen;
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, 32, EVP_sha256(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
    HMAC_Final(ctx, hmac, &hmacLen);
    HMAC_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(hmac), hmacLen);
}

bool PersistentMemory::verifyHMAC(const unsigned char* key, const std::string& data, const std::string& receivedHMAC) {
    std::string computedHMAC = generateHMAC(key, data);
    return computedHMAC == receivedHMAC;
}

void PersistentMemory::addUser(const User& user) {
    mUserMap[user.getNickname()] = user;
    saveToFile();
}

void PersistentMemory::addMessage(const Message& message) {
    mMessageMap[message.getUUID()] = message;
    saveToFile();
}

std::vector<User> PersistentMemory::getUsers() {
    std::vector<User> users;
    for (const auto& pair : mUserMap) {
        users.push_back(pair.second);
    }
    return users;
}

std::vector<Message> PersistentMemory::getMessages() {
    std::vector<Message> messages;
    for (const auto& pair : mMessageMap) {
        messages.push_back(pair.second);
    }
    return messages;
}

std::vector<Message> PersistentMemory::getMessages(size_t n) {
    std::vector<Message> messages;
    for (const auto& pair : mMessageMap) {
        messages.push_back(pair.second);
    }

    std::sort(messages.begin(), messages.end(), [](const Message& a, const Message& b) {
        return a.getCreationTime() > b.getCreationTime();
    });

    if (n > messages.size()) {
        n = messages.size();
    }

    return std::vector<Message>(messages.begin(), messages.begin() + static_cast<std::vector<Message>::difference_type>(n));
}

User PersistentMemory::getUser(const std::string& nickname) {
    auto it = mUserMap.find(nickname);
    if (it != mUserMap.end()) {
        return it->second;
    }
    throw UserNotFoundException();
}

Message PersistentMemory::getMessage(const std::string& uuid) {
    auto it = mMessageMap.find(uuid);
    if (it != mMessageMap.end()) {
        return it->second;
    }
    throw MessageNotFoundException();
}

void PersistentMemory::removeUser(const std::string& nickname) {
    mUserMap.erase(nickname);
    saveToFile();
}

void PersistentMemory::removeMessage(const std::string& uuid) {
    mMessageMap.erase(uuid);
    saveToFile();
}
