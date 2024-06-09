#include "cryptomanager.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <sys/stat.h>

CryptoManager::CryptoManager(const std::string& privateKeyPath, const std::string& publicKeyPath)
    : privateKeyPath(privateKeyPath), publicKeyPath(publicKeyPath) {}

bool CryptoManager::fileExists(const std::string& fileName) {
    struct stat buffer;
    return (stat(fileName.c_str(), &buffer) == 0);
}

bool CryptoManager::generateRSAKey() {
    if (fileExists(privateKeyPath) || fileExists(publicKeyPath)) {
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("Errore nella creazione del contesto per la chiave");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Errore nell'inizializzazione del contesto per la chiave");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Errore nella configurazione della lunghezza della chiave RSA");
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Errore nella generazione della chiave RSA");
    }

    EVP_PKEY_CTX_free(ctx);

    FILE *privateFile = fopen(privateKeyPath.c_str(), "wb");
    if (!privateFile) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Errore nell'apertura del file per la chiave privata");
    }

    if (!PEM_write_PrivateKey(privateFile, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(privateFile);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Errore nella scrittura della chiave privata su file");
    }
    fclose(privateFile);

    FILE *publicFile = fopen(publicKeyPath.c_str(), "wb");
    if (!publicFile) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Errore nell'apertura del file per la chiave pubblica");
    }

    if (!PEM_write_PUBKEY(publicFile, pkey)) {
        fclose(publicFile);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Errore nella scrittura della chiave pubblica su file");
    }
    fclose(publicFile);

    EVP_PKEY_free(pkey);

    return true;
}