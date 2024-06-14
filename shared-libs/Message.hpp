#pragma once

#include "UUID.hpp"
#include <string>
#include <iostream>
#include <chrono>

class Message {
    private:
        std::string mUUID = uuid::generate_uuid_v4();
        std::string mTitle;
        std::string mAuthor;
        std::string mBody;
        long long mCreationTime;

    public:
        Message() : mTitle(""), mAuthor(""), mBody(""), mCreationTime(0) {} // Costruttore di default
        Message(const std::string& title, const std::string& author, const std::string& body) : mTitle(title), mAuthor(author), mBody(body) {
            mCreationTime = std::chrono::system_clock::now().time_since_epoch().count();
            mUUID = uuid::generate_uuid_v4();
        }

        std::string getUUID() const { return mUUID; }
        std::string getTitle() const { return mTitle; }
        std::string getAuthor() const { return mAuthor; }
        std::string getBody() const { return mBody; }
        long long getCreationTime() const { return mCreationTime; }
};
