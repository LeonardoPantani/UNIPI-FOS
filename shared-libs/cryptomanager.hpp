#pragma once

#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <sys/stat.h>

class CryptoManager {
public:
    CryptoManager(const std::string& privateKeyPath, const std::string& publicKeyPath);

    bool generateRSAKey();

private:
    std::string privateKeyPath;
    std::string publicKeyPath;

    bool fileExists(const std::string& fileName);
};