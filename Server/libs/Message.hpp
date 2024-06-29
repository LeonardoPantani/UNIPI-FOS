#pragma once
#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include "UUID.hpp"
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>

class Message {
    private:
        std::string mUUID;
        std::string mTitle;
        std::string mAuthor;
        std::string mBody;
        long long mCreationTime;

    public:
        Message() : mUUID(""), mTitle(""), mAuthor(""), mBody(""), mCreationTime(0) {} // Costruttore di default

        Message(const std::string& uuid, const std::string& title, const std::string& author, const std::string& body, const long long creationTime) : mUUID(uuid), mTitle(title), mAuthor(author), mBody(body), mCreationTime(creationTime) {

        }
        
        Message(const std::string& title, const std::string& author, const std::string& body) : mTitle(title), mAuthor(author), mBody(body) {
            mCreationTime = std::chrono::system_clock::now().time_since_epoch().count();
            mUUID = uuid::generate_uuid_v4();
        }

        std::string getUUID() const { return mUUID; }
        std::string getTitle() const { return mTitle; }
        std::string getAuthor() const { return mAuthor; }
        std::string getBody() const { return mBody; }
        long long getCreationTime() const { return mCreationTime; }
        
        std::string getFormattedCreationTime() const {
            std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::time_point(std::chrono::nanoseconds(mCreationTime));
            std::time_t creationTime = std::chrono::system_clock::to_time_t(timePoint);
            std::tm* tm = std::localtime(&creationTime);
            const char* months[] = {"gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"};
            std::ostringstream oss;
            oss << std::put_time(tm, "%d ") << months[tm->tm_mon] << std::put_time(tm, " %Y alle %H:%M:%S");
            return oss.str();
        }
};

#endif