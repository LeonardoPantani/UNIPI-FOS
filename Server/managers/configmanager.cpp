#include "configmanager.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

ConfigManager::ConfigManager(const std::string& configPath) {
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        std::string defaultConfigPath = "libs/default-config.conf";
        initializeDefaultConfig(defaultConfigPath, configPath);
        std::cout << "> Configuration file created from default. Please modify 'config.conf' as needed and restart the program." << std::endl;
        exit(0);
    }

    loadConfig(configPath);
}

void ConfigManager::initializeDefaultConfig(const std::string& defaultConfigPath, const std::string& configPath) {
    std::ifstream defaultConfigFile(defaultConfigPath);
    std::ofstream newConfigFile(configPath);
    if (defaultConfigFile.is_open() && newConfigFile.is_open()) {
        newConfigFile << defaultConfigFile.rdbuf();
    }
}

void ConfigManager::loadConfig(const std::string& configPath) {
    std::ifstream configFile(configPath);
    std::string line;
    while (getline(configFile, line)) {
        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, ':')) {
            std::string value;
            if (std::getline(is_line, value)) {
                configValues[key] = value;
            }
        }
    }
}

std::string ConfigManager::getString(const std::string& key) {
    return configValues[key];
}

int ConfigManager::getInt(const std::string& key) {
    return std::stoi(configValues[key]);
}
