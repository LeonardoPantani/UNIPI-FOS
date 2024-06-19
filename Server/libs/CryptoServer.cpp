#include "CryptoServer.hpp"

CryptoServer::CryptoServer(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath) {
    // memorizzo CA
    FILE* file = fopen(caPath.c_str(), "r");
    if (!file) {
        throw std::runtime_error("Unable to open CA certificate file at path " + caPath + ".");
    }
    X509* caCert = PEM_read_X509(file, NULL, NULL, NULL);
    if (!caCert) {
        throw std::runtime_error("Unable to read the CA certificate.");
    }
    fclose(file);

    // memorizzo CRL
    file = fopen(crlPath.c_str(), "r");
    if (!file) {
        throw std::runtime_error("Unable to open certificate revocation list file at path " + crlPath + ".");
    }
    X509_CRL* crl = PEM_read_X509_CRL(file, NULL, NULL, NULL);
    if (!crl) {
        throw std::runtime_error("Unable to read the certificate revocation list.");
    }
    fclose(file);

    // costruisco lo store
    mStore = X509_STORE_new();
    X509_STORE_add_cert(mStore, caCert);
    X509_STORE_add_crl(mStore, crl);
    X509_STORE_set_flags(mStore, X509_V_FLAG_CRL_CHECK);

    // leggo certificato da file
    file = fopen(ownCertificatePath.c_str(), "r");
    if (!file) {
        throw std::runtime_error("Unable to open certificate file at path " + ownCertificatePath + ".");
    }
    X509* ownCert = PEM_read_X509(file, NULL, NULL, NULL);
    if (!ownCert) {
        throw std::runtime_error("Unable to read the certificate.");
    }
    fclose(file);

    // verifico il mio stesso certificato
    if (verifyCertificate(ownCert)) {
        storeCertificate(ownCert);
    } else {
        throw std::runtime_error("Unable to verify own certificate.");
    }

    
    /* gestione parametri */
    mDHParams = EVP_PKEY_new();
}

CryptoServer::~CryptoServer() {
    X509_STORE_free(mStore);
}

bool CryptoServer::storeCertificate(X509* toStore) {
    if (X509_STORE_add_cert(mStore, toStore) == -1) {
        return false; // impossibile aggiungere
    } else {
        return true; // ok
    }
}

bool CryptoServer::verifyCertificate(X509* toValidate) {
    // Verifying a client certificate with a store
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, mStore, toValidate, NULL);
    int ret = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    if (ret != 1) {
        return false; // authentication error
    } else {
        return true; // valid
    }
}



// DHKEP
void CryptoServer::printDHParameters() {
    if (!mDHParams) {
        std::cerr << "I parametri DH non sono stati generati." << std::endl;
        return;
    }

    EVP_PKEY_print_params_fp(stdout, mDHParams, 0, NULL);
}

void CryptoServer::printPubKey() {
    // Creazione del contesto BIO per l'output in memoria
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Errore nella creazione del BIO in memoria" << std::endl;
        return;
    }

    // Scrittura della chiave pubblica in formato PEM nel BIO
    if (PEM_write_bio_PUBKEY(bio, mPeerPublicKey) <= 0) {
        std::cerr << "Errore nella scrittura della chiave pubblica in formato PEM" << std::endl;
        BIO_free(bio);
        return;
    }

    // Lettura del contenuto del BIO in una stringa
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string pubKeyStr(mem->data, mem->length);

    // Pulizia del BIO
    BIO_free(bio);

    // Stampa della chiave pubblica
    std::cout << pubKeyStr << std::endl;
}

std::string CryptoServer::prepareDHParams() {
    // Creare un contesto per generare i parametri DH
    EVP_PKEY_CTX* paramgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!paramgen_ctx) {
        throw std::runtime_error("Unable to create EVP_PKEY_CTX.");
    }

    // Inizializzare il contesto per la generazione dei parametri
    if (EVP_PKEY_paramgen_init(paramgen_ctx) <= 0) {
        EVP_PKEY_CTX_free(paramgen_ctx);
        throw std::runtime_error("Unable to initialize parameter generation context.");
    }

    // Specificare la dimensione del primo parametro (ad esempio, 2048 bit)
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramgen_ctx, 1024) <= 0) {
        EVP_PKEY_CTX_free(paramgen_ctx);
        throw std::runtime_error("Unable to set prime length.");
    }

    // Generare i parametri DH
    if (EVP_PKEY_paramgen(paramgen_ctx, &mDHParams) <= 0) {
        EVP_PKEY_CTX_free(paramgen_ctx);
        throw std::runtime_error("Unable to generate DH parameters.");
    }

    // Pulire il contesto
    EVP_PKEY_CTX_free(paramgen_ctx);

    // Estrarre i parametri p e g
    const DH* dh = EVP_PKEY_get0_DH(mDHParams);
    if (!dh) {
        throw std::runtime_error("Unable to get DH parameters.");
    }

    const BIGNUM* p = nullptr;
    const BIGNUM* g = nullptr;
    DH_get0_pqg(dh, &p, nullptr, &g);

    if (!p || !g) {
        throw std::runtime_error("Unable to extract p and g.");
    }

    // Convertire i parametri p e g in stringa
    char* p_str = BN_bn2hex(p);
    char* g_str = BN_bn2hex(g);

    if (!p_str || !g_str) {
        throw std::runtime_error("Unable to convert p and g to string.");
    }

    std::ostringstream oss;
    oss << p_str << " " << g_str;

    // Liberare le stringhe allocate da BN_bn2hex
    OPENSSL_free(p_str);
    OPENSSL_free(g_str);

    return oss.str();
}

std::string CryptoServer::preparePublicKey() {
    // Creazione del contesto per la generazione della chiave
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(mDHParams, NULL);
    if (!ctx) {
        throw std::runtime_error("Errore nella creazione del contesto EVP_PKEY_CTX");
    }

    // Inizializzazione della generazione della chiave
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Errore nell'inizializzazione della generazione della chiave");
    }

    // Generazione della chiave privata
    if (EVP_PKEY_keygen(ctx, &mMyPrivateKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Errore nella generazione della chiave privata");
    }

    // Pulizia del contesto
    EVP_PKEY_CTX_free(ctx);

    // Creazione del contesto BIO per l'output in memoria
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Errore nella creazione del BIO in memoria");
    }

    // Scrittura della chiave pubblica in formato PEM nel BIO
    if (PEM_write_bio_PUBKEY(bio, mMyPrivateKey) <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Errore nella scrittura della chiave pubblica in formato PEM");
    }

    // Lettura del contenuto del BIO in una stringa
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string pubKeyStr(mem->data, mem->length);

    // Pulizia del BIO
    BIO_free(bio);

    return pubKeyStr;
}

void CryptoServer::receivePublicKey(const std::string& peerPublicKey) {
    // Creazione del contesto BIO in memoria per la chiave pubblica
    BIO* bio = BIO_new_mem_buf(peerPublicKey.data(), static_cast<int>(peerPublicKey.size()));
    if (!bio) {
        throw std::runtime_error("Errore nella creazione del BIO in memoria");
    }

    // Lettura della chiave pubblica dal BIO
    mPeerPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!mPeerPublicKey) {
        BIO_free(bio);
        throw std::runtime_error("Errore nella lettura della chiave pubblica dal BIO");
    }

    // Pulizia del BIO
    BIO_free(bio);
}