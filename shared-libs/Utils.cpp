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

// lettura nascosta della password. Purtroppo va separata per Windows (mostra *) e Linux (non mostra l'input)
std::string readPassword() {
    std::string password;
    bool illegalPassword = false;

    do {
        std::cout << (illegalPassword ? "\n" : "") << "Inserisci password: ";
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
            struct termios oldt, newt;
            tcgetattr(STDIN_FILENO, &oldt);
            newt = oldt;
            newt.c_lflag &= static_cast<tcflag_t>(~ECHO);
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