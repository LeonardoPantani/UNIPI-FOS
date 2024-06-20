#pragma once
#ifndef CRYPTOCLIENT_HPP
#define CRYPTOCLIENT_HPP

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

class CryptoClient {
    private:
        X509_STORE* mStore;

        EVP_PKEY* mDHParams = nullptr;

        EVP_PKEY* mMySecret = nullptr; // a (esponente segreto)
        EVP_PKEY* mMyPublicKey = nullptr; // g^a mod p
        EVP_PKEY* mPeerPublicKey = nullptr;

    public:
        CryptoClient(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath);
        ~CryptoClient();

        bool storeCertificate(X509* certificate);
        bool verifyCertificate(X509* toValidate);

        void printDHParameters();
        void printPubKey();

        void receiveDHParameters(const std::string& dhParamsStr);
        std::string preparePublicKey();
        void receivePublicKey(const std::string& peerPublicKey);
};

#endif