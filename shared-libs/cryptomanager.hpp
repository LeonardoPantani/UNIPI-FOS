#pragma once

#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <sys/stat.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

class CryptoManager {
public:
    CryptoManager(const std::string& privateKeyPath, const std::string& publicKeyPath);
    CryptoManager();

    bool generateRSAKey();

    std::pair<unsigned char*, int> getCertFromFile(const std::string& certFilePath);

private:
    std::string mPrivateKeyPath;
    std::string mPublicKeyPath;

    bool fileExists(const std::string& fileName);
};