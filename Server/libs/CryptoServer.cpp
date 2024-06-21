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

        X509_free(caCert);
        X509_CRL_free(crl);

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

        X509_free(ownCert);
    } catch(std::runtime_error const&) {
        fclose(file);
        throw;
    }
}

CryptoServer::~CryptoServer() {
    X509_STORE_free(mStore);
    EVP_PKEY_free(mDHParams);
    EVP_PKEY_free(mMyPublicKey);

    for (auto it = mPeersPublicKeys.begin(); it != mPeersPublicKeys.end(); ++it) {
        EVP_PKEY_free(it->second);          // Libera la memoria allocata per EVP_PKEY
    }

    // Dopo aver liberato tutti gli elementi, svuota la mappa
    mPeersPublicKeys.clear();
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
        EVP_PKEY_free(privKey);
        throw std::runtime_error("Invalid private key file provided at path " + mOwnPrivateKeyPath + ".");
    }

    unsigned char* signature = static_cast<unsigned char*>(malloc(EVP_PKEY_size(privKey)));
    unsigned int signature_len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, pair.c_str(), pair.length());
    EVP_SignFinal(ctx, signature, &signature_len, privKey);
    EVP_PKEY_free(privKey);
    EVP_MD_CTX_free(ctx);

    std::string toRet(reinterpret_cast<char*>(signature), signature_len);
    free(signature);
    return toRet;
}

std::vector<char> CryptoServer::encryptSignatureWithK(int client_socket, std::string signedPair) {
    EVP_CIPHER_CTX* ctx;
    const unsigned char* key = reinterpret_cast<const unsigned char*>(mPeersK[client_socket].data());
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(signedPair.data());

    std::vector<unsigned char> ciphertext(signedPair.size() + EVP_MAX_BLOCK_LENGTH);
    int cipherlen;
    int outlen;

    /* Context allocation */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    /* Encryption (initialization + single update + finalization) */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, msg, signedPair.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    cipherlen = outlen;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + cipherlen, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    cipherlen += outlen;

    /* Context deallocation */
    EVP_CIPHER_CTX_free(ctx);

    std::vector<char> encrypted(cipherlen);
    std::copy(ciphertext.begin(), ciphertext.begin() + cipherlen, encrypted.begin());
    
    return encrypted;
}

std::vector<char> CryptoServer::decryptSignatureWithK(int client_socket, std::vector<char> signedEncryptedPair) {
    EVP_CIPHER_CTX* ctx;
    const unsigned char* key = reinterpret_cast<const unsigned char*>(mPeersK[client_socket].data());
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(signedEncryptedPair.data());
    int cipherlen = signedEncryptedPair.size();
    
    std::vector<unsigned char> plaintext(cipherlen);
    int plainlen;
    int outlen;

    /* Context allocation */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    /* Decryption (initialization + single update + finalization) */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext, cipherlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plainlen = outlen;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + plainlen, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    plainlen += outlen;

    /* Context deallocation */
    EVP_CIPHER_CTX_free(ctx);

    std::vector<char> decrypted(plainlen);
    std::copy(plaintext.begin(), plaintext.begin() + plainlen, decrypted.begin());
    
    return decrypted;
}

// chiamata dal server, fornisce {<g^b, g^a>B}k
std::string CryptoServer::prepareSignedPair(int client_socket) {
    return base64_encode(encryptSignatureWithK(client_socket, signWithPrivKey(client_socket)));
}

EVP_PKEY* CryptoServer::extractPubKeyFromCert(std::string clientCertificate) {
    // Creare un buffer di memoria dalla stringa del certificato
    BIO* bio = BIO_new_mem_buf(clientCertificate.data(), clientCertificate.size());
    if (!bio) {
        throw std::runtime_error("Impossibile creare buffer di memoria.");
    }

    // Leggere il certificato X509 dal buffer
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio); // Rilasciare il buffer
    if (!cert) {
        throw std::runtime_error("Il certificato è illeggibile.");
    }

    // Estrarre la chiave pubblica dal certificato X509
    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    X509_free(cert); // Rilasciare il certificato
    if (!pubKey) {
        throw std::runtime_error("Impossibile estrarre la chiave pubblica.");
    }

    // Restituire la chiave pubblica
    return pubKey;
}

void CryptoServer::verifySignature(int client_socket, std::vector<char> signedPair, EVP_PKEY* serverCertificatePublicKey) {
    // Ricostruire coppia: g^b g^a
    std::string reconstructedPair = keyToString(mMyPublicKey) + " " + keyToString(mPeersPublicKeys[client_socket]);

    // Estrai i dati dal pair ricostruito
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(reconstructedPair.c_str());
    int msg_len = static_cast<int>(reconstructedPair.size());

    // Estrai i dati dalla firma
    const unsigned char* signature = reinterpret_cast<const unsigned char*>(signedPair.data());
    int signature_len = static_cast<int>(signedPair.size());

    // Inizializza il contesto per la verifica
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Inizializzazione contesto fallita.");
    }

    // Inizializza la verifica con SHA-256
    if (EVP_VerifyInit(ctx, EVP_sha256()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Inizializzazione verifica firma fallita.");
    }

    // Aggiungi il messaggio alla verifica
    if (EVP_VerifyUpdate(ctx, msg, msg_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Aggiornamento verifica firma fallito.");
    }

    // Esegui la verifica finale
    int ret = EVP_VerifyFinal(ctx, signature, signature_len, serverCertificatePublicKey);
    EVP_MD_CTX_free(ctx);

    // Verifica il risultato
    if (ret != 1) {
        throw std::runtime_error("La firma non è valida.");
    }
}

void CryptoServer::varCheck(int client_socket, std::string serverCertificate, std::vector<char> clientSignedEncryptedPair) {
    std::vector<char> signedPair = decryptSignatureWithK(client_socket, clientSignedEncryptedPair);
    EVP_PKEY* certPubKey = extractPubKeyFromCert(serverCertificate);
    
    try {
        verifySignature(client_socket, signedPair, certPubKey);
        EVP_PKEY_free(certPubKey);
    } catch(std::exception const&e) {
        EVP_PKEY_free(certPubKey);
        throw std::runtime_error(std::string("Errore varCheck: ") + e.what());
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

    EVP_PKEY_free(mMySecret); // delete esponente segreto b
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