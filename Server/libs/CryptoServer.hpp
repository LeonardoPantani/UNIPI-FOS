#pragma once
#ifndef CRYPTOSERVER_HPP
#define CRYPTOSERVER_HPP

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

/// @brief Classe che fornisce numerosi metodi per il funzionamento sicuro e privato del programma. Versione: Server (B)
class CryptoServer {
    private:
        X509_STORE* mStore; // la store che contiene: certificato CA, CRL, mio certificato
        ASN1_INTEGER* mOwnCertificationSerialNumber; // il SN del proprio certificato
        EVP_PKEY* mDHParameters = nullptr; // p, g
        std::map<int, EVP_PKEY*> mMySecret; // b (esponente segreto)
        std::map<int, EVP_PKEY*> mMyPublicKey; // g^b mod p
        std::map<int, EVP_PKEY*> mPeersPublicKeys; // g^a mod p
        std::map<int, std::string> mPeersK; // K in comune coi client
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

        /// @brief (privata) Firma la coppia <g^a, g^b>_privKey con la propria chiave privata (di default nel file "server_priv.pem")
        /// @param client_socket il client di cui firmare la coppia
        /// @return stringa contenente la coppia firmata
        std::string signWithPrivateKey(int client_socket);

        /// @brief (privata) Cifra la coppia <g^a, g^b>_privKey utilizzando K_AB cioè la chiave condivisa generata con (Y_a)^b mod p = g^(a*b) mod p
        /// @param client_socket il client di cui cifrare la coppia
        /// @param signedPair la coppia di cifrare
        /// @return vettore di caratteri contenente la coppia cifrata con K_AB
        std::vector<char> encryptSignatureWithK(int client_socket, std::string signedPair);

        /// @brief (privata) Decifra la coppia <g^a, g^b>_privKey (del client) utilizzando K_AB cioè la chiave condivisa generata con (Y_a)^b mod p = g^(a*b) mod p
        /// @param client_socket il client di cui decifrare la coppia
        /// @param signedEncryptedPair la coppia da decifrare
        /// @return vettore di caratteri contenente la coppia firmata
        std::vector<char> decryptSignatureWithK(int client_socket, std::vector<char> signedEncryptedPair);

        /// @brief Data la coppia firmata (già decifrata), verifica la firma
        /// @param client_socket il client di cui verificare la firma
        /// @param signedPair la coppia <g^a, g^b>_privKey (del client)
        /// @param peerPublicKey la chiave pubblica dell'altro interlocutore per la verifica della firma
        void verifySignature(int client_socket, std::vector<char> signedPair, EVP_PKEY* peerPublicKey);
    
    
    public:
        CryptoServer(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath);
        ~CryptoServer();

        /// @brief Rimuove tutte le informazioni crittografiche relative ad un client. Viene chiamata alla chiusura della comunicazione.
        /// @param client_socket il client di cui effettuare la pulizia
        void removeClientSocket(int client_socket);

        /// @brief Cerca il certificato del server nella store e lo prepara per l'invio al client
        /// @return il proprio certificato, come stringa
        std::string prepareCertificate();

        /// @brief Prende la coppia <g^a, g^b>, la concatena in una stringa "g^a g^b", la firma con la propria chiave privata (del certificato) e la cifra con K_AB
        /// @param client_socket il client di cui preparare la coppia firmata
        /// @return la coppia firmata, criptata e codificata in base64
        std::string prepareSignedPair(int client_socket);

        /// @brief Genera i parametri p (2048 bit) e g
        /// @return la stringa pronta per essere spedita nel formato "p g"
        std::string prepareDHParameters();

        /// @brief Genera la chiave pubblica del server per uno specifico client
        /// @param client_socket il client a cui si deve spedire la chiave pubblica
        /// @return la chiave pubblica generata in formato stringa
        std::string preparePublicKey(int client_socket);

        /// @brief Memorizza la chiave pubblica del client nella classe CryptoServer
        /// @param client_socket il client di cui memorizzare la chiave pubblica
        /// @param peerPublicKey la chiave pubblica del client ricevuta come stringa
        void receivePublicKey(int client_socket, const std::string& peerPublicKey);

        /// @brief Deriva K_AB = (Y_A)^b mod p = g^(a*b) mod p
        /// @param client_socket il client di cui derivare la K_AB
        void derivateK(int client_socket);

        /// @brief Decripta con K_AB la coppia criptata e firmata, verifica il certificato del server, ne estrae la chiave pubblica e ci verifica la firma decriptata
        /// @param clientCertificate il certificato nel server
        /// @param clientSignedEncryptedPair la coppia criptata e firmata {<g^a, g^b>}
        void varCheck(int client_socket, std::string clientCertificate, std::vector<char> clientSignedEncryptedPair);

        /// @brief Manda un messaggio cifrato
        /// @param toEncrypt il vettore di caratteri contenente il messaggio da cifrare
        /// @param nonce il nonce da inserire nel messaggio cifrato
        /// @return il messaggio cifrato
        std::vector<char> encryptSessionMessage(int client_socket, std::vector<char> toEncrypt, long *nonce);
        
        /// @brief Riceve un messaggio cifrato
        /// @param buffer il buffer contenente il messaggio cifrato
        /// @param size la dimensione del buffer in byte ricevuti
        /// @param nonce il valore del nonce memorizzato (verrà incrementato da questa funzione) da verificare
        /// @return il messaggio decifrato
        std::vector<char> decryptSessionMessage(int client_socket, const char* buffer, size_t size, long *nonce);
};

#endif