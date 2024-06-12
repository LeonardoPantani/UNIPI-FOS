#pragma once

#include "UUID.hpp"
#include <string>
#include <iostream>
#include <chrono>

class Message {
    private:
        std::string uuid = uuid::generate_uuid_v4();
        std::string title;
        std::string author;
        std::string body;
        long long creationTime;

    public:
        Message() : title(""), author(""), body("") {} // Costruttore di default
        Message(const std::string& title, const std::string& author, const std::string& body) {
            this->title = title;
            this->author = author;
            this->body = body;
            this->creationTime = std::chrono::system_clock::now().time_since_epoch().count();
            this->uuid = uuid::generate_uuid_v4();
        }

        std::string getUUID() const { return uuid; }
        std::string getTitle() const { return title; }
        std::string getAuthor() const { return author; }
        std::string getBody() const { return body; }
        long long getCreationTime() const { return creationTime; }
};
