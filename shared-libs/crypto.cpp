#include "crypto.hpp"

Crypto::Crypto(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath) {
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
}

Crypto::~Crypto() {
    X509_STORE_free(mStore);
}

bool Crypto::storeCertificate(X509* toStore) {
    if (X509_STORE_add_cert(mStore, toStore) == -1) {
        return false; // impossibile aggiungere
    } else {
        return true; // ok
    }
}

bool Crypto::verifyCertificate(X509* toValidate) {
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
void Crypto::printDHParameters() {
    if (!mDHParams) {
        std::cerr << "I parametri DH non sono stati generati." << std::endl;
        return;
    }

    EVP_PKEY_print_params_fp(stdout, mDHParams, 0, NULL);
}

std::string Crypto::prepareDHParams() {
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


void Crypto::setDHParams(const std::string& dhParamsStr) {
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

    std::cout << "P:" << BN_bn2hex(p) << " | G: " << BN_bn2hex(g) << std::endl;

    DH* dh = DH_new();
    if (!dh || !DH_set0_pqg(dh, p, NULL, g)) {
        if (dh) DH_free(dh);
        if (p) BN_free(p);
        if (g) BN_free(g);
        throw std::runtime_error("Unable to set DH parameters.");
    }

    

    // Assegnare i parametri DH a mDHParams
    if (!EVP_PKEY_set1_DH(mDHParams, dh)) {
        DH_free(dh);
        throw std::runtime_error("Unable to assign DH parameters to EVP_PKEY.");
    }

    EVP_PKEY_print_params_fp(stdout, mDHParams, 0, NULL);
}