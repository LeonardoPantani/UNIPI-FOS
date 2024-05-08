#include "managers/configmanager.hpp"
#include <iostream>

int main() {
    /* =======================================
        loading config values from config.conf file
       ======================================= */
    try {
        std::string configPath = "config.conf";
        ConfigManager configManager(configPath);

        std::string version = configManager.getString("version");
        int serverPort = configManager.getInt("serverPort");
        int maxMessageLength = configManager.getInt("maxMessageLength");

        std::cout << "FILE DI CONFIGURAZIONE CARICATO: " << std::endl;
        std::cout << "> Versione: " << version << std::endl;
        std::cout << "> Porta server: " << serverPort << std::endl;
        std::cout << "> Massima lunghezza messaggi: " << maxMessageLength << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[!] Errore: " << e.what() << std::endl;
        return 1;
    }
    
    /* =======================================
        open server to public
       ======================================= */
    
    // TODO
    return 0;
}
