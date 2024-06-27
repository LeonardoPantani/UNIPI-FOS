#include "Utils.hpp"

// Funzione che genera un codice numerico casuale di x cifre
std::string generateVerificationCode(size_t digitsToGenerate) {
    std::string result;

    unsigned char randomByte;
    for (size_t i = 0; i < digitsToGenerate; ++i) {
        if (RAND_bytes(&randomByte, sizeof(randomByte)) != 1) {
            throw std::runtime_error("Errore generazione codice di verifica.");
        }
        int randomDigit = randomByte % 10; // numero tra 0 e 9
        result += std::to_string(randomDigit);
    }

    return result;
}

// Funzione che genera un numero casuale con generatore non-deterministico a 32 bit
long generateRandomLong() {
    long random_value;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&random_value), sizeof(random_value)) != 1) {
        throw std::runtime_error("Errore generazione numero long casuale.");
    }
    random_value = random_value & 0x7FFFFFFFFFFFFFFF; // rendo il numero forzatamente positivo
    return random_value;
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

// Funzione per validare un'email tramite regex
bool isValidEmail(const std::string& email) {
    const std::regex pattern(R"((\w+)(\.{1}\w+)*@(\w+)(\.{1}\w+)*(\.\w{2,})+)");
    return std::regex_match(email, pattern);
}

// Funzione per validare lunghezza degli argomenti
bool validateLength(const std::string& arg, size_t maxLength) {
    return arg.length() <= maxLength;
}

// Funzione che verifica la validità di un uuid
bool isValidUUID(const std::string& uuid) {
    const std::regex pattern(R"([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})");
    return std::regex_match(uuid, pattern);
}

// Funzione di codifica base 64
std::string base64_encode(const std::vector<char>& input) {
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignora i nuovi linee
    BIO_write(b64, input.data(), input.size());
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string output(bptr->data, bptr->length);
    BIO_free_all(b64);

    return output;
}

// Funzione di decodifica base 64
std::vector<char> base64_decode(const std::string &encoded) {
    BIO *b64, *bmem;
    size_t decodedLength = encoded.length();
    std::vector<char> buffer(decodedLength);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(encoded.data(), encoded.length());
    bmem = BIO_push(b64, bmem);

    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL); // Ignora i nuovi linee
    int decodedSize = BIO_read(bmem, buffer.data(), encoded.length());
    if (decodedSize < 0) {
        BIO_free_all(bmem);
        throw std::runtime_error("Error decoding base64");
    }

    buffer.resize(decodedSize);
    BIO_free_all(bmem);

    return buffer;
}

void overwriteSecret(std::string &toOverwrite) {
    std::memset(&toOverwrite[0], 0, toOverwrite.size()); // imposta a 0
    toOverwrite.clear(); // libera la memoria ridimensionando a 0
    toOverwrite.shrink_to_fit(); // forza il rilascio
}