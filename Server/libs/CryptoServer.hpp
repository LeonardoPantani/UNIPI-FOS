#pragma once
#ifndef CRYPTOSERVER_HPP
#define CRYPTOSERVER_HPP

#include "../../shared-libs/json.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/dh.h>
#include <openssl/param_build.h>
#include <iostream>
#include <stdexcept>
#include <vector>

class CryptoServer {
    private:
        X509_STORE* mStore;
        ASN1_INTEGER* mOwnCertSN;
        EVP_PKEY* mDHParams = nullptr; // p, g
        EVP_PKEY* mMyPublicKey = nullptr; // g^b
        EVP_PKEY* mMySecret = nullptr; // b (esponente segreto)

        std::map<int, EVP_PKEY*> mPeersPublicKeys;
        std::map<int, std::string> mPeersK;

        std::string mOwnPrivateKeyPath;

    public:
        CryptoServer(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath);
        ~CryptoServer();

        void printCertificate(X509* cert);
        bool storeCertificate(X509* certificate);
        bool verifyCertificate(X509* toValidate);
        std::string prepareCertificate();
        void printAllCertificates();

        void printDHParameters();
        std::string keyToString(EVP_PKEY* toConvert);
        void printPubKey(int client_socket);


        std::string signWithPrivKey(int client_socket);
        std::string prepareSignedPair(int client_socket);
        std::string encryptWithK(int client_socket, std::string signedPair);

        std::string prepareDHParams();
        void setDHParams(const std::string& dhParamsStr);
        std::string preparePublicKey();
        void receivePublicKey(int client_socket, const std::string& peerPublicKey);
        void derivateK(int client_socket);
};

#endif