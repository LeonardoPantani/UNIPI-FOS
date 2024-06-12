#include "configmanager.hpp"
#include "json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

const std::string defaultConfigPath = "libs/default-config.json";

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

    loadConfig(configPath, configValues);

    switch(checkVersion()) {
        case 1: {
            std::cout << "[!] Impossibile ottenere i dati sulla versione. Cancella l'attuale configurazione e ri-esegui questo programma per generare quello nuovo." << std::endl;
            exit(1);
        }
        break;
        case 2: {
            std::cout << "[!] E' disponibile una nuova versione del file di configurazione. Cancella l'attuale configurazione e ri-esegui questo programma per generare quello nuovo." << std::endl;
            exit(1);
        }
        break;
        case 3: {
            std::cout << "[!] Il tuo file di configurazione è più recente del default. Scarica gli aggiornamenti di questo programma e ri-eseguilo." << std::endl;
            exit(1);
        }
        break;

        default: {}
    }

    if(!loadConfig(configPath, configValues)) {
        std::cerr << "[!] File di configurazione non valido. Eliminalo e riesegui il programma per continuare." << std::endl;
        exit(1);
    }
}

bool ConfigManager::loadConfig(const std::string& configPath, std::unordered_map<std::string, std::string>& storage) {
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) return false;

    json configJson;
    configFile >> configJson;

    for (const auto& key : configKeys) {
        if (configJson.contains(key)) {
            if (configJson[key].is_string()) {
                storage[key] = configJson[key].get<std::string>();
            } else if (configJson[key].is_number_integer()) {
                storage[key] = std::to_string(configJson[key].get<int>());
            } else if (configJson[key].is_number_float()) {
                std::stringstream ss;
                ss << std::fixed << std::setprecision(1) << configJson[key];
                storage[key] = ss.str();;
            }
        }
    }

    return std::all_of(configKeys.begin(), configKeys.end(), [&storage](const std::string& key) {
        return !storage[key].empty();
    });
}

/**
 * 0 ok
 * 1 impossibile ottenere versione utente
 * 2 versione utente più vecchia
 * 3 versione utente più recente
 */
int ConfigManager::checkVersion() {
    std::string defaultVersion = defaultConfigValues["configVersion"];
    std::string userVersion = configValues["configVersion"];

    if (userVersion.empty()) return 1;

    if (userVersion > defaultVersion) {
        return 3;
    } else if (userVersion < defaultVersion) {
        return 2;
    }
    return 0;
}

std::string ConfigManager::getString(const std::string& key) {
    return configValues[key];
}

int ConfigManager::getInt(const std::string& key) {
    return std::stoi(configValues[key]);
}
