#include "Utils.hpp"

// Funzione che genera un codice numerico casuale di x cifre
std::string generateVerificationCode(size_t digitsToGenerate) {
    std::random_device rd; 
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9); 
    std::string result;
    for (size_t i = 0; i < digitsToGenerate; ++i) {
        int randomNumber = dis(gen);
        result += std::to_string(randomNumber);
    }
    return result;
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