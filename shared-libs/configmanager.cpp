#include "configmanager.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

const std::string defaultConfigPath = "libs/default-config.conf";

ConfigManager::ConfigManager(const std::string& configPath, const std::vector<std::string>& configKeys) : configKeys(configKeys) {
    if(!loadConfig(defaultConfigPath, defaultConfigValues)) {
        std::cerr << "[!] Installazione corrotta: la configurazione di default al percorso " << defaultConfigPath << " non esiste o non è valida." << std::endl;
        exit(1);
    }

    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        fs::copy(defaultConfigPath, configPath, fs::copy_options::overwrite_existing);
        std::cout << "> File di configurazione creato. Modifica " << configPath << " se necessario e riesegui il programma per continuare." << std::endl;
        exit(0);
    }
    
    if(!loadConfig(configPath, configValues)) {
        std::cerr << "[!] File di configurazione non valido. Eliminalo e riesegui il programma per continuare." << std::endl;
        exit(1);
    }
}

bool ConfigManager::loadConfig(const std::string& configPath, std::unordered_map<std::string, std::string>& storage) {
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) return false;

    std::string line;
    while (getline(configFile, line)) {
        std::istringstream is_line(line);
        std::string key, value;
        if (std::getline(is_line, key, ':') && std::getline(is_line, value))
            storage[key] = value;
    }
    return std::all_of(configKeys.begin(), configKeys.end(), [&storage](const std::string& key) {
        return !storage[key].empty();
    });
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