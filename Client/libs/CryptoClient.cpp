#include "CryptoClient.hpp"

CryptoClient::CryptoClient(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath) {
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

        X509_free(ownCert);
        X509_free(caCert);
        X509_CRL_free(crl);
    } catch(std::runtime_error const&) {
        fclose(file);
        throw;
    }
}

CryptoClient::~CryptoClient() {
    X509_STORE_free(mStore);
    EVP_PKEY_free(mDHParams);
    EVP_PKEY_free(mMyPublicKey);
    EVP_PKEY_free(mPeerPublicKey);
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

std::string CryptoClient::prepareCertificate() {
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
std::string CryptoClient::signWithPrivKey() {
    std::string pair = keyToString(mPeerPublicKey) + " " + keyToString(mMyPublicKey);

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
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privKey);

    std::string toRet(reinterpret_cast<char*>(signature), signature_len);
    free(signature);
    return toRet;
}

std::vector<char> CryptoClient::encryptSignatureWithK(std::string signedPair) {
    EVP_CIPHER_CTX* ctx;
    const unsigned char* key = reinterpret_cast<const unsigned char*>(mPeerK.data());
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
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)) {
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

std::vector<char> CryptoClient::decryptSignatureWithK(std::vector<char> signedEncryptedPair) {
    EVP_CIPHER_CTX* ctx;
    const unsigned char* key = reinterpret_cast<const unsigned char*>(mPeerK.data());
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
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key, nullptr)) {
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

// chiamata dal client, fornisce {<g^b, g^a>A}k
std::string CryptoClient::prepareSignedPair() {
    std::string signedPair = signWithPrivKey();
    std::vector<char> encryptedSignedPair = encryptSignatureWithK(signedPair);
    return base64_encode(encryptedSignedPair);
}

EVP_PKEY* CryptoClient::extractPubKeyFromCert(std::string serverCertificate) {
    // Creare un buffer di memoria dalla stringa del certificato
    BIO* bio = BIO_new_mem_buf(serverCertificate.data(), serverCertificate.size());
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

void CryptoClient::verifySignature(std::vector<char> signedPair, EVP_PKEY* serverCertificatePublicKey) {
    // Ricostruire coppia: g^b g^a
    std::string reconstructedPair = keyToString(mPeerPublicKey) + " " + keyToString(mMyPublicKey);

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

void CryptoClient::varCheck(std::string serverCertificate, std::vector<char> serverSignedEncryptedPair) {
    std::vector<char> signedPair = decryptSignatureWithK(serverSignedEncryptedPair);
    
    try {
        EVP_PKEY* certPublicKey = extractPubKeyFromCert(serverCertificate);
        verifySignature(signedPair, certPublicKey);
        EVP_PKEY_free(certPublicKey);
    } catch(std::exception const&e) {
        throw std::runtime_error(std::string("Errore varCheck: ") + e.what());
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

std::string CryptoClient::keyToString(EVP_PKEY* toConvert) {
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
        DH_free(DH);
        throw std::runtime_error("Unable to assign DH parameters to EVP_PKEY.");
    }
    DH_free(DH);
}

// Genera g^a
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

    // Generazione di a (esponente segreto)
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

    // Dato mMySecret (a), scrive in bio g^a mod p
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

void CryptoClient::derivateK() {
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(mMySecret, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, mPeerPublicKey);

    size_t secretlen;
    EVP_PKEY_derive(ctx_drv, NULL, &secretlen);

    std::vector<unsigned char> secret(secretlen);
    EVP_PKEY_derive(ctx_drv, secret.data(), &secretlen);

    EVP_PKEY_CTX_free(ctx_drv);

    std::string secret_str(secret.begin(), secret.end());

    mPeerK = secret_str;

    EVP_PKEY_free(mMySecret); // delete esponente segreto a
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


// [nonce (8), packetType (4), dato (?)]
std::vector<char> CryptoClient::encryptSessionMessage(std::vector<char> toEncrypt, long *nonce) {
    if(*nonce == 0) {
        *nonce = generateRandomLong(); // al messaggio successivo al termine dell'handshake verrà usato questo nonce casuale
    } else {
        *nonce += 1;
    }
    // aggiungiamo nonce a toEncrypt all'inizio in modo che assuma il formato descritto sopra ^^
    std::vector<char> nonceBytes(sizeof(long));
    std::memcpy(nonceBytes.data(), nonce, sizeof(long));
    toEncrypt.insert(toEncrypt.begin(), nonceBytes.begin(), nonceBytes.end());

    // cifratura
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Impossibile creare contesto.");
    }

    unsigned char iv[12]; // GCM standard IV size is 12 bytes
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        throw std::runtime_error("Impossibile generare IV casuale.");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        throw std::runtime_error("Errore EncryptInit_ex.");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1) {
        throw std::runtime_error("Errore CIPHER_CTX_ctrl.");
    }

    const unsigned char* key = reinterpret_cast<const unsigned char*>(mPeerK.data());

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        throw std::runtime_error("Errore EncryptInit_ex.");
    }

    int len;
    ciphertext.resize(toEncrypt.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(toEncrypt.data()), toEncrypt.size()) != 1) {
        throw std::runtime_error("Errore EncryptUpdate.");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        throw std::runtime_error("Errore EncryptFinal_ex.");
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);

    tag.resize(16); // GCM standard tag size is 16 bytes
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) {
        throw std::runtime_error("Errore CIPHER_CTX_ctrl.");
    }

    EVP_CIPHER_CTX_free(ctx);

    nlohmann::json jsonData;
    jsonData["data"] = ciphertext;
    jsonData["iv"] = iv;
    jsonData["tag"] = tag;

    std::string jsonString = jsonData.dump();
    std::vector<char> jsonVector(jsonString.begin(), jsonString.end());

    return jsonVector;
}

// chi manda i dati (li cripta forse) non pulisce e quindi se il messaggio prima era più lungo rimane anche in quello nuovo

std::vector<char> CryptoClient::decryptSessionMessage(const char* buffer, size_t size, long *nonce) {
    std::string json_str(buffer, size);
    std::vector<char> plaintext;

    nlohmann::json msg = nlohmann::json::parse(json_str);
    std::vector<unsigned char> data = msg["data"];
    std::vector<unsigned char> iv = msg["iv"];
    std::vector<unsigned char> tag = msg["tag"];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Impossibile creare contesto.");
    }

    const unsigned char* key = reinterpret_cast<const unsigned char*>(mPeerK.data());

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore DecryptInit_ex.");
    }

    int len;
    std::vector<unsigned char> plaintext_buf(data.size() + EVP_MAX_BLOCK_LENGTH);
    if (EVP_DecryptUpdate(ctx, plaintext_buf.data(), &len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore DecryptUpdate.");
    }
    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), reinterpret_cast<void*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore CIPHER_CTX_ctrl.");
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext_buf.data() + plaintext_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Errore DecryptFinal_ex.");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext_buf.resize(plaintext_len);
    plaintext.assign(plaintext_buf.begin(), plaintext_buf.end());

    // Estrai i primi 8 byte di plaintext e convertili in un numero long
    long toVerifyNonce;
    std::memcpy(&toVerifyNonce, plaintext.data(), sizeof(long));
    if(toVerifyNonce != ++*nonce) {
        throw std::runtime_error("Nonce del messaggio non corrisponde.");
    }
    plaintext.erase(plaintext.begin(), plaintext.begin() + sizeof(long));

    return plaintext;
}
