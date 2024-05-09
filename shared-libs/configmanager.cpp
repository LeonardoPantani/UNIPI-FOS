#include "configmanager.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

const std::string defaultConfigPath = "libs/default-config.conf";

ConfigManager::ConfigManager(const std::string& configPath) {
    loadConfig(defaultConfigPath, defaultConfigValues);
    loadConfig(configPath, configValues);
}

void ConfigManager::loadConfig(const std::string& configPath, std::unordered_map<std::string, std::string>& storage) {
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        std::cerr << "[!] Impossibile aprire file di configurazione: " << configPath << std::endl;
        exit(1);
    }

    std::string line;
    while (getline(configFile, line)) {
        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, ':')) {
            std::string value;
            if (std::getline(is_line, value)) {
                storage[key] = value;
            }
        }
    }
}

bool ConfigManager::checkVersion() {
    std::string defaultVersion = defaultConfigValues["configVersion"];
    std::string userVersion = configValues["configVersion"];
    if (userVersion > defaultVersion) {
        std::cout << "[!] Il tuo file di configurazione è più recente del default. Scarica gli aggiornamenti di questo programma e ri-eseguilo." << std::endl;
        return false;
    } else if (userVersion < defaultVersion) {
        std::cout << "[!] E' disponibile una nuova versione del file di configurazione. Cancella l'attuale configurazione e ri-esegui questo programma per generare quello nuovo." << std::endl;
        return false;
    }
    return true;
}

std::string ConfigManager::getString(const std::string& key) {
    return configValues[key];
}

int ConfigManager::getInt(const std::string& key) {
    return std::stoi(configValues[key]);
}