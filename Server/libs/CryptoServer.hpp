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

class CryptoServer {
    private:
        X509_STORE* mStore;
        ASN1_INTEGER* mOwnCertificationSerialNumber;
        EVP_PKEY* mDHParameters = nullptr; // p, g
        std::map<int, EVP_PKEY*> mMyPublicKey; // g^b
        std::map<int, EVP_PKEY*> mMySecret; // b (esponente segreto)
        std::map<int, EVP_PKEY*> mPeersPublicKeys; // chiavi pubbliche dei client
        std::map<int, std::string> mPeersK; // K dei client
        std::map<int, EVP_PKEY*> mHMACKeys; // chiavi che usa il server per ottenere lo stesso HMAC tra client e server
        std::string mOwnPrivateKeyPath;

    
        // metodi privati
        bool storeCertificate(X509* certificate);
        bool verifyCertificate(X509* toValidate);
        std::string keyToString(EVP_PKEY* toConvert);
        std::string signWithPrivateKey(int client_socket);
        std::vector<char> encryptSignatureWithK(int client_socket, std::string signedPair);
        std::vector<char> decryptSignatureWithK(int client_socket, std::vector<char> signedEncryptedPair);
        void setDHParams(const std::string& dhParamsStr);


    public:
        CryptoServer(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath);
        ~CryptoServer();

        void removeClientSocket(int client_socket);
        std::string prepareCertificate();
        std::string prepareSignedPair(int client_socket);
        std::string prepareDHParameters();
        std::string preparePublicKey(int client_socket);
        void receivePublicKey(int client_socket, const std::string& peerPublicKey);
        void derivateK(int client_socket);
        std::vector<char> encryptSessionMessage(int client_socket, std::vector<char> toEncrypt, long *nonce);
        std::vector<char> decryptSessionMessage(int client_socket, const char* buffer, size_t size, long *nonce);
        EVP_PKEY* extractPublicKeyFromCertificate(std::string serverCertificate);
        void verifySignature(int client_socket, std::vector<char> signedPair, EVP_PKEY* serverCertificatePublicKey);
        void varCheck(int client_socket, std::string serverCertificate, std::vector<char> clientSignedEncryptedPair);
};

#endif