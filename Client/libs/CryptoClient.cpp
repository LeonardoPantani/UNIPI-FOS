#include "CryptoClient.hpp"

CryptoClient::CryptoClient(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath) {
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

CryptoClient::~CryptoClient() {
    X509_STORE_free(mStore);
}

bool CryptoClient::storeCertificate(X509* toStore) {
    if (X509_STORE_add_cert(mStore, toStore) == -1) {
        return false; // impossibile aggiungere
    } else {
        return true; // ok
    }
}

bool CryptoClient::verifyCertificate(X509* toValidate) {
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
void CryptoClient::printDHParameters() {
    if (!mDHParams) {
        std::cerr << "I parametri DH non sono stati generati." << std::endl;
        return;
    }

    EVP_PKEY_print_params_fp(stdout, mDHParams, 0, NULL);
}

void CryptoClient::printPubKey() {
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



void CryptoClient::receiveDHParameters(const std::string& dhParamsStr) {
    std::istringstream iss(dhParamsStr);
    std::string p_hex, g_hex;

    if (!(iss >> p_hex >> g_hex)) {
        throw std::runtime_error("Invalid DH parameters string format.");
    }

    BIGNUM* p = BN_new();
    BIGNUM* g = BN_new();

    if (!BN_hex2bn(&p, p_hex.c_str()) || !BN_hex2bn(&g, g_hex.c_str())) {
        if (p) BN_free(p);
        if (g) BN_free(g);
        throw std::runtime_error("Unable to convert hex to BIGNUM.");
    }

    DH* DH = DH_new();
    // Creating and Setting DH Parameters
    if (DH == nullptr) { 
        if (p) BN_free(p); 
        if (g) BN_free(g);
        throw std::runtime_error("Unable to create DH structure."); 
    }

    int ret = DH_set0_pqg(DH, p, NULL, g);
    if (ret != 1) {
        DH_free(DH);
        if (p) BN_free(p);
        if (g) BN_free(g);
        throw std::runtime_error("Unable to set DH parameters (DH_set0_pqg failed)."); 
    }

    // Validate DH parameters
    int codes;
    if (DH_check(DH, &codes) != 1 || (codes != 0)) {
        DH_free(DH);
        if (p) BN_free(p);
        if (g) BN_free(g);
        throw std::runtime_error("Invalid DH parameters.");
    }

    // Assign DH Parameters to EVP_PKEY
    if (!EVP_PKEY_set1_DH(mDHParams, DH)) {
        // EVP_PKEY_set1_DH takes ownership of dh, so no need to DH_free here.
        throw std::runtime_error("Unable to assign DH parameters to EVP_PKEY.");
    }
}

std::string CryptoClient::preparePublicKey() {
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

void CryptoClient::receivePublicKey(const std::string& peerPublicKey) {
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