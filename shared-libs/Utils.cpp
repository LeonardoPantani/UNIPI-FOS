#include "Utils.hpp"

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