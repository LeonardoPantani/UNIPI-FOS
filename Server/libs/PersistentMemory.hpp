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

#include "User.hpp"
#include "Message.hpp"

#include "../../shared-libs/json.hpp"

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

    public:
        PersistentMemory(const std::string& dataFilePath, const std::string& keyFilePath);
        PersistentMemory();
        ~PersistentMemory();

        void addUser(const User& user);
        void addMessage(const Message& message);

        std::vector<User> getUsers();
        std::vector<Message> getMessages();

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