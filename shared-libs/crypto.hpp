#pragma once
#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include "json.hpp"
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

class Crypto {
    private:
        X509_STORE* mStore;
        EVP_PKEY* mDHParams = EVP_PKEY_new();

    public:
        Crypto(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath);
        ~Crypto();

        bool storeCertificate(X509* certificate);
        bool verifyCertificate(X509* toValidate);

        void printDHParameters();

        std::string prepareDHParams();
        void setDHParams(const std::string& dhParamsStr);
};

#endif