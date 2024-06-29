#pragma once
#ifndef CRYPTOCLIENT_HPP
#define CRYPTOCLIENT_HPP

#include "../../shared-libs/Json.hpp"
#include "../../shared-libs/Utils.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdexcept>
#include <vector>

/// @brief Classe che fornisce numerosi metodi per il funzionamento sicuro e privato del programma. Versione: Client (A)
class CryptoClient {
    private:
        X509_STORE* mStore; // la store che contiene: certificato CA, CRL, mio certificato
        ASN1_INTEGER* mOwnCertificationSerialNumber; // il SN del proprio certificato
        EVP_PKEY* mDHParameters = nullptr; // p, g
        EVP_PKEY* mMySecret = nullptr; // a (esponente segreto)
        EVP_PKEY* mMyPublicKey = nullptr; // g^a mod p
        EVP_PKEY* mPeerPublicKey = nullptr; // g^b mod p
        std::string mPeerK; // K in comune col server
        std::string mOwnPrivateKeyPath; // il percorso della chiave privata


        // -------- metodi privati --------


        /// @brief (privata) converte una stringa in formato PEM in certificato X509
        /// @param toConvert la stringa da convertire
        /// @return il certificato in formato X509
        X509* stringToCertificate(const std::string& toConvert);

        /// @brief (privata) Aggiunge un certificato alla store (con la funzione X509_STORE_add_cert)
        /// @param certificate il certificato da aggiungere
        /// @return TRUE se il certificato è stato aggiunto, FALSE altrimenti
        bool storeCertificate(X509* certificate);

        /// @brief (privata) Verifica la validità del certificato all'interno della store
        /// @param toValidate il certificato da validare
        /// @return TRUE se il certificato è valido, FALSE altrimenti
        bool verifyCertificate(X509* toValidate);

        /// @brief Estrae la chiave pubblica da un certificato in formato stringa
        /// @param certificate il certificato da cui estrarre la chiave pubblica
        /// @return la chiave pubblica estratta
        EVP_PKEY* extractPublicKeyFromCertificate(std::string certificate);

        /// @brief (privata) Converte un chiave PKEY in std::string
        /// @param toConvert la chiave da convertire
        /// @return la chiave convertita in stringa
        std::string keyToString(EVP_PKEY* toConvert);

        /// @brief (privata) Firma la coppia <g^a, g^b>_privKey con la propria chiave privata (di default nel file "client_priv.pem")
        /// @return stringa contenente la coppia firmata
        std::string signWithPrivateKey();

        /// @brief (privata) Cifra la coppia <g^a, g^b>_privKey utilizzando K_AB cioè la chiave condivisa generata con (Y_B)^a mod p = g^(b*a) mod p
        /// @param signedPair la coppia di cifrare
        /// @return vettore di caratteri contenente la coppia cifrata con K_AB
        std::vector<char> encryptSignatureWithK(std::string signedPair);

        /// @brief (privata) Decifra la coppia <g^a, g^b>_privKey (del server) utilizzando K_AB cioè la chiave condivisa generata con (Y_B)^a mod p = g^(b*a) mod p
        /// @param signedEncryptedPair la coppia da decifrare
        /// @return vettore di caratteri contenente la coppia firmata
        std::vector<char> decryptSignatureWithK(std::vector<char> signedEncryptedPair);

        /// @brief Data la coppia firmata (già decifrata), verifica la firma
        /// @param signedPair la coppia <g^a, g^b>_privKey (del server)
        /// @param peerPublicKey la chiave pubblica dell'altro interlocutore per la verifica della firma
        void verifySignature(std::vector<char> signedPair, EVP_PKEY* peerPublicKey);


    public:
        CryptoClient(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath);
        ~CryptoClient();

        /// @brief Cerca il certificato del client nella store e lo prepara per l'invio al server
        /// @return il proprio certificato, come stringa
        std::string prepareCertificate();

        /// @brief Prende la coppia <g^a, g^b>, la concatena in una stringa "g^a g^b", la firma con la propria chiave privata (del certificato) e la cifra con K_AB
        /// @return la coppia firmata, criptata e codificata in base64
        std::string prepareSignedPair();

        /// @brief Data la stringa nel formato "p g" contenente i parametri DH p (2048 bit) e g, li memorizza nella classe CryptoClient
        /// @param dhParamsStr la stringa contenente "p g" ricevuta dal server
        void receiveDHParameters(const std::string& dhParamsStr);

        /// @brief Genera la chiave pubblica del client
        /// @return la chiave pubblica generata in formato stringa
        std::string preparePublicKey();

        /// @brief Memorizza la chiave pubblica del server (DH) nella classe CryptoClient
        /// @param peerPublicKey la chiave pubblica del server ricevuta come stringa
        void receivePublicKey(const std::string& peerPublicKey);

        /// @brief Deriva K_AB = (Y_B)^A mod p = g^(b*a) mod p
        void derivateK();

        /// @brief Decripta con K_AB la coppia criptata e firmata, verifica il certificato del server, ne estrae la chiave pubblica e ci verifica la firma decriptata
        /// @param serverCertificate il certificato nel server
        /// @param serverSignedEncryptedPair la coppia criptata e firmata {<g^a, g^b>}
        void varCheck(std::string serverCertificate, std::vector<char> serverSignedEncryptedPair);

        /// @brief Manda un messaggio cifrato
        /// @param toEncrypt il vettore di caratteri contenente il messaggio da cifrare
        /// @param nonce il nonce da inserire nel messaggio cifrato
        /// @return il messaggio cifrato
        std::vector<char> encryptSessionMessage(std::vector<char> toEncrypt, long *nonce);

        /// @brief Riceve un messaggio cifrato
        /// @param buffer il buffer contenente il messaggio cifrato
        /// @param size la dimensione del buffer in byte ricevuti
        /// @param nonce il valore del nonce memorizzato (verrà incrementato da questa funzione) da verificare
        /// @return il messaggio decifrato
        std::vector<char> decryptSessionMessage(const char* buffer, size_t size, long *nonce);
};

#endif