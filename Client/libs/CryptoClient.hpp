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

class CryptoClient {
    private:
        X509_STORE* mStore;
        ASN1_INTEGER* mOwnCertificationSerialNumber;
        EVP_PKEY* mDHParameters = nullptr;
        EVP_PKEY* mMySecret = nullptr; // a (esponente segreto)
        EVP_PKEY* mMyPublicKey = nullptr; // g^a mod p
        EVP_PKEY* mPeerPublicKey = nullptr; // g^b mod p
        std::string mPeerK;
        std::string mOwnPrivateKeyPath;

        // metodi privati
        bool storeCertificate(X509* certificate);
        bool verifyCertificate(X509* toValidate);
        std::string keyToString(EVP_PKEY* toConvert);
        std::string signWithPrivateKey();
        std::vector<char> decryptSignatureWithK(std::vector<char> signedEncryptedPair);
        std::vector<char> encryptSignatureWithK(std::string signedPair);
        EVP_PKEY* extractPublicKeyFromCertificate(std::string serverCertificate);
        void verifySignature(std::vector<char> signedPair, EVP_PKEY* serverCertificatePublicKey);


    public:
        CryptoClient(const std::string& caPath, const std::string& crlPath, const std::string& ownCertificatePath, const std::string& ownPrivateKeyPath);
        ~CryptoClient();

        std::string prepareCertificate();
        std::string prepareSignedPair();
        void receiveDHParameters(const std::string& dhParamsStr);
        std::string preparePublicKey();
        void receivePublicKey(const std::string& peerPublicKey);
        void derivateK();
        void varCheck(std::string serverCertificate, std::vector<char> serverSignedEncryptedPair);
        std::vector<char> encryptSessionMessage(std::vector<char> toEncrypt, long *nonce);
        std::vector<char> decryptSessionMessage(const char* buffer, size_t size, long *nonce);
};

#endif