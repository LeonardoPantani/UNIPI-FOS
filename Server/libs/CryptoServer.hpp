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

        EVP_PKEY* mDHParams = nullptr;

        EVP_PKEY* mMyPrivateKey = nullptr;
        EVP_PKEY* mPeerPublicKey = nullptr;

    public:
        CryptoServer(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath);
        ~CryptoServer();

        bool storeCertificate(X509* certificate);
        bool verifyCertificate(X509* toValidate);

        void printDHParameters();
        void printPubKey();

        std::string prepareDHParams();
        void setDHParams(const std::string& dhParamsStr);
        std::string preparePublicKey();
        void receivePublicKey(const std::string& peerPublicKey);
};

#endif