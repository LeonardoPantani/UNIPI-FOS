#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "User.hpp"
#include "../../shared-libs/json.hpp"
#include "../../shared-libs/Message.hpp"

class PersistentMemory {
    private:
        std::string filePath;
        std::string keyFilePath;
        unsigned char key[32];
        unsigned char iv[16];
        std::unordered_map<std::string, User> userMap;
        std::unordered_map<std::string, Message> messageMap;

        bool loadKey();
        void saveKey();
        bool loadFromFile();
        void saveToFile();
        std::string encrypt(const std::string& plainText);
        std::string decrypt(const std::string& cipherText);

    public:
        PersistentMemory(const std::string& filePath, const std::string& keyFilePath);
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