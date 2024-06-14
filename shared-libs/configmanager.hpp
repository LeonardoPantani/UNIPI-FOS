#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <algorithm>

class ConfigManager {
private:
    std::unordered_map<std::string, std::string> mConfigValues;
    std::unordered_map<std::string, std::string> mDefaultConfigValues;
    std::vector<std::string> mConfigKeys;

    const std::string mDefaultConfigPath = "libs/default-config.json";

public:
    ConfigManager(const std::string& configPath, const std::vector<std::string>& configKeys);

    bool loadConfig(const std::string& configPath, std::unordered_map<std::string, std::string>& storage);
    int checkVersion();
    std::string getString(const std::string& key);
    int getInt(const std::string& key);
};
