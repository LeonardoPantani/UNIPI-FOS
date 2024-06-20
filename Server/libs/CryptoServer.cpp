#include "CryptoServer.hpp"

CryptoServer::CryptoServer(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath) {
    FILE* file;
    try {
        // memorizzo CA
        file = fopen(caPath.c_str(), "r");
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
        if (!verifyCertificate(ownCert)) {
            throw std::runtime_error("Unable to verify own certificate.");
        }

        // controllo presenza chiave privata del certificato (non la valido ancora)
        file = fopen(ownPrivateKeyPath.c_str(), "r");
        if (!file) {
            throw std::runtime_error("Unable to open private key file at path " + ownPrivateKeyPath + ".");
        }
        fclose(file);
        mOwnPrivateKeyPath = ownPrivateKeyPath;

        storeCertificate(ownCert);
        mOwnCertSN = X509_get_serialNumber(ownCert);
        
        /* gestione parametri */
        mDHParams = EVP_PKEY_new();
    } catch(std::runtime_error const&) {
        fclose(file);
        throw;
    }
    fclose(file);
}

CryptoServer::~CryptoServer() {
    X509_STORE_free(mStore);
}

void CryptoServer::printCertificate(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_X509(bio, cert)) {
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        std::string cert_str(data, len);
        std::cout << cert_str << std::endl;
    } else {
        throw std::runtime_error("Unable to print certificate.");
    }
    BIO_free(bio);
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

void CryptoServer::printAllCertificates() {
    // Iterate over the certificates in the store
    STACK_OF(X509_OBJECT)* objects = X509_STORE_get0_objects(mStore);
    if (objects) {
        for (int i = 0; i < sk_X509_OBJECT_num(objects); ++i) {
            X509_OBJECT* obj = sk_X509_OBJECT_value(objects, i);
            if (X509_OBJECT_get_type(obj) == X509_LU_X509) {
                X509* cert = X509_OBJECT_get0_X509(obj);
                printCertificate(cert);
            }
        }
    } else {
        std::cerr << "No objects in the X509_STORE" << std::endl;
    }
}

std::string CryptoServer::prepareCertificate() {
    STACK_OF(X509_OBJECT)* objects = X509_STORE_get0_objects(mStore);
    if (!objects) {
        throw std::runtime_error("Nessun oggetto trovato nella store.");
    }

    for (int i = 0; i < sk_X509_OBJECT_num(objects); ++i) {
        X509_OBJECT* obj = sk_X509_OBJECT_value(objects, i);
        if (X509_OBJECT_get_type(obj) == X509_LU_X509) {
            X509* cert = X509_OBJECT_get0_X509(obj);

            if (X509_get_serialNumber(cert) == mOwnCertSN) {
                std::string cert_pem;

                // Creazione di un BIO per memorizzare la rappresentazione PEM del certificato
                BIO* bio = BIO_new(BIO_s_mem());
                if (bio) {
                    // Scrittura del certificato X509 nel BIO in formato PEM
                    if (PEM_write_bio_X509(bio, cert)) {
                        // Leggi i dati dal BIO
                        char* buffer;
                        long length = BIO_get_mem_data(bio, &buffer);

                        if (length > 0 && buffer) {
                            cert_pem.assign(buffer, length);
                        }
                    }
                    // Liberazione del BIO
                    BIO_free(bio);
                }

                return cert_pem;
            }
        }
    }

    return "";
}




// funzione intermedia privat: firma la coppia <g^b, g^a>
std::string CryptoServer::signWithPrivKey(int client_socket) {
    std::string pair = keyToString(mMyPublicKey) + " " + keyToString(mPeersPublicKeys[client_socket]);

    // carico da file la chiave privata (esponente b)
    FILE* fp = fopen(mOwnPrivateKeyPath.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("Unable to open private key file at path " + mOwnPrivateKeyPath + ".");
    }
    
    EVP_PKEY* privKey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!privKey) {
        throw std::runtime_error("Invalid private key file provided at path " + mOwnPrivateKeyPath + ".");
    }

    unsigned char* signature = static_cast<unsigned char*>(malloc(EVP_PKEY_size(privKey)));
    unsigned int signature_len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, pair.c_str(), pair.length());
    EVP_SignFinal(ctx, signature, &signature_len, privKey);
    EVP_MD_CTX_free(ctx);

    std::string toRet(reinterpret_cast<char*>(signature), signature_len);
    return toRet;
}

std::string CryptoServer::encryptWithK(int client_socket, std::string signedPair) {
    // TODO Criptare signedPair con k del client_socket

    return "";
}
// chiamata dal server, fornisce {<g^b, g^a>b}k
std::string CryptoServer::prepareSignedPair(int client_socket) {
    return encryptWithK(client_socket, signWithPrivKey(client_socket));
}

// DHKEP
void CryptoServer::printDHParameters() {
    if (!mDHParams) {
        std::cerr << "I parametri DH non sono stati generati." << std::endl;
        return;
    }

    EVP_PKEY_print_params_fp(stdout, mDHParams, 0, NULL);
}

std::string CryptoServer::keyToString(EVP_PKEY* toConvert) {
    // Creazione del contesto BIO per l'output in memoria
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("Errore nella creazione del BIO in memoria.");
    }

    // Scrittura della chiave pubblica in formato PEM nel BIO
    if (PEM_write_bio_PUBKEY(bio, toConvert) <= 0) {        
        BIO_free(bio);
        throw std::runtime_error("Errore nella scrittura della chiave pubblica in formato PEM");
    }

    // Lettura del contenuto del BIO in una stringa
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string converted(mem->data, mem->length);

    // Pulizia del BIO
    BIO_free(bio);

    return converted;
}

void CryptoServer::printPubKey(int client_socket) {
    std::cout << keyToString(mPeersPublicKeys[client_socket]) << std::endl;
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

// Genera g^b
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

    // Dato mMySecret (b), scrive in bio g^b mod p
    if (EVP_PKEY_keygen(ctx, &mMySecret) <= 0) {
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
    if (PEM_write_bio_PUBKEY(bio, mMySecret) <= 0) {
        BIO_free(bio);
        throw std::runtime_error("Errore nella scrittura della chiave pubblica in formato PEM");
    }

    // Lettura del contenuto del BIO in una stringa
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string pubKeyStr(mem->data, mem->length);

    // Memorizza la chiave pubblica in formato EVP_PKEY*
    mMyPublicKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    // Pulizia del BIO
    BIO_free(bio);

    return pubKeyStr;
}

void CryptoServer::derivateK(int client_socket) {
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(mMySecret, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, mPeersPublicKeys[client_socket]);

    size_t secretlen;
    EVP_PKEY_derive(ctx_drv, NULL, &secretlen);

    std::vector<unsigned char> secret(secretlen);
    EVP_PKEY_derive(ctx_drv, secret.data(), &secretlen);

    EVP_PKEY_CTX_free(ctx_drv);

    std::string secret_str(secret.begin(), secret.end());

    mPeersK.insert({client_socket, secret_str});
}

void CryptoServer::receivePublicKey(int client_socket, const std::string& peerPublicKey) {
    // Creazione del contesto BIO in memoria per la chiave pubblica
    BIO* bio = BIO_new_mem_buf(peerPublicKey.data(), static_cast<int>(peerPublicKey.size()));
    if (!bio) {
        throw std::runtime_error("Errore nella creazione del BIO in memoria");
    }

    // Lettura della chiave pubblica dal BIO
    mPeersPublicKeys.insert({client_socket, PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)});
    if (!mPeersPublicKeys[client_socket]) {
        BIO_free(bio);
        throw std::runtime_error("Errore nella lettura della chiave pubblica dal BIO");
    }

    // Pulizia del BIO
    BIO_free(bio);
}