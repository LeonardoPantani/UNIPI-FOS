#pragma once
#ifndef PERSISTENTMEMORY_HPP
#define PERSISTENTMEMORY_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "User.hpp"
#include "Message.hpp"

#include "../../shared-libs/Json.hpp"

class PersistentMemory {
    private:
        std::string mDataFilePath;
        std::string mKeyFilePath;
        unsigned char mKey[32];
        unsigned char mIV[16];
        std::unordered_map<std::string, User> mUserMap;
        std::unordered_map<std::string, Message> mMessageMap;

        bool loadKey();
        void saveKey();
        bool loadFromFile();
        void saveToFile();
        std::string encrypt(const std::string& plainText);
        std::string decrypt(const std::string& cipherText);
        std::string generateHMAC(const unsigned char* key, const std::string& data);
        bool verifyHMAC(const unsigned char* key, const std::string& data, const std::string& receivedHMAC);

    public:
        PersistentMemory(const std::string& dataFilePath, const std::string& keyFilePath);
        PersistentMemory();
        ~PersistentMemory();

        void addUser(const User& user);
        void addMessage(const Message& message);

        std::vector<User> getUsers();
        std::vector<Message> getMessages();
        std::vector<Message> getMessages(size_t n);

        User getUser(const std::string& email);
        Message getMessage(const std::string& uuid);

        void removeUser(const std::string& email);
        void removeMessage(const std::string& uuid);
};

class UserNotFoundException : public std::exception {
public:
    const char* what() const noexcept override {
        return "";
    }
};
class MessageNotFoundException : public std::exception {
public:
    const char* what() const noexcept override {
        return "";
    }
};

#endif