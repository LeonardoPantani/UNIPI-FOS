#include "cryptomanager.hpp"

CryptoManager::CryptoManager(const std::string& privateKeyPath, const std::string& publicKeyPath)
    : mPrivateKeyPath(privateKeyPath), mPublicKeyPath(publicKeyPath) {}

CryptoManager::CryptoManager()
    : mPrivateKeyPath("key.priv"), mPublicKeyPath("key.pub") {}

bool CryptoManager::fileExists(const std::string& fileName) {
    struct stat buffer;
    return (stat(fileName.c_str(), &buffer) == 0);
}

bool CryptoManager::generateRSAKey() {
    if (fileExists(mPrivateKeyPath) || fileExists(mPublicKeyPath)) {
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

    FILE *privateFile = fopen(mPrivateKeyPath.c_str(), "wb");
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

    FILE *publicFile = fopen(mPublicKeyPath.c_str(), "wb");
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

std::pair<unsigned char*, int> CryptoManager::getCertFromFile(const std::string& certFilePath) {
    X509 *x509 = nullptr;
    BIO *certBio = BIO_new(BIO_s_file());
    unsigned char *buf = nullptr;

    if (!certBio) {
        throw std::runtime_error("Errore nella creazione di un oggetto BIO per il file del certificato");
    }

    if (BIO_read_filename(certBio, certFilePath.c_str()) <= 0) {
        BIO_free(certBio);
        throw std::runtime_error("Errore nella lettura del file del certificato");
    }

    // Leggi il certificato X509 dal BIO
    x509 = d2i_X509_bio(certBio, nullptr);
    if (!x509) {
        BIO_free(certBio);
        throw std::runtime_error("Errore nella lettura del certificato X509");
    }

    // Ottieni la lunghezza del certificato in formato DER
    int len = i2d_X509(x509, &buf);
    if (len <= 0) {
        BIO_free(certBio);
        X509_free(x509);
        throw std::runtime_error("Errore nella conversione del certificato X509 in formato DER");
    }

    // Libera il BIO
    BIO_free(certBio);

    // Restituisci il certificato in formato DER e la sua lunghezza
    return std::make_pair(buf, len);
}