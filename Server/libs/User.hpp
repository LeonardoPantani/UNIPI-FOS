#pragma once
#ifndef USER_HPP
#define USER_HPP

#include <string>
#include <vector>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>

class User {
    private:
        std::string mEmail;
        std::string mNickname;
        std::vector<uint8_t> mPassword;
        std::vector<uint8_t> mSalt;
        long long mCreationTime;

        static const size_t SALT_SIZE = 16; // Dimensione del salt in byte
        static const size_t HASH_SIZE = 32; // Dimensione dell'hash SHA-256

        std::vector<uint8_t> generateSalt() {
            std::vector<uint8_t> salt(SALT_SIZE);
            if (RAND_bytes(salt.data(), SALT_SIZE) != 1) {
                throw std::runtime_error("Errore generazione del salt.");
            }
            return salt;
        }

        std::vector<uint8_t> hashPassword(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt) const {
            std::vector<uint8_t> hash(HASH_SIZE);
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                throw std::runtime_error("Failed to create EVP_MD_CTX");
            }

            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
                EVP_DigestUpdate(ctx, salt.data(), salt.size()) != 1 ||
                EVP_DigestUpdate(ctx, password.data(), password.size()) != 1 ||
                EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("Impossibile fare hash della password.");
            }

            EVP_MD_CTX_free(ctx);
            return hash;
        }

    public:
        User() : mEmail(""), mNickname(""), mPassword({}), mSalt({}), mCreationTime(0) {}

        User(const std::string& email, const std::string& nickname, const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, const long long creationTime)
            : mEmail(email), mNickname(nickname), mPassword(password), mSalt(salt), mCreationTime(creationTime) {
        }

        User(const std::string& email, const std::string& nickname, const std::string& password) : mEmail(email), mNickname(nickname), mSalt(generateSalt()) {
            std::vector<uint8_t> passwordVec(password.begin(), password.end());
            mPassword = hashPassword(passwordVec, mSalt);
            mCreationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
        }

        std::string getEmail() const { return mEmail; }
        std::string getNickname() const { return mNickname; }
        std::vector<uint8_t> getPassword() const { return mPassword; }
        std::vector<uint8_t> getSalt() const { return mSalt; }
        long long getCreationTime() const { return mCreationTime; }

        bool checkPassword(const std::string& password) const {
            std::vector<uint8_t> passwordVec(password.begin(), password.end());
            std::vector<uint8_t> hash = hashPassword(passwordVec, mSalt);
            return hash == mPassword;
        }

        // Metodo per convertire i byte in una stringa esadecimale (utile per debugging)
        std::string bytesToHex(const std::vector<uint8_t>& bytes) const {
            std::ostringstream oss;
            for (auto byte : bytes) {
                oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte);
            }
            return oss.str();
        }
};

#endif