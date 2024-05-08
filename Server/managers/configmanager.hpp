#pragma once

#include <string>
#include <unordered_map>

class ConfigManager {
public:
    ConfigManager(const std::string& configPath);
    std::string getString(const std::string& key);
    int getInt(const std::string& key);

private:
    std::unordered_map<std::string, std::string> configValues;
    void loadConfig(const std::string& configPath);
    void initializeDefaultConfig(const std::string& defaultConfigPath, const std::string& configPath);
};