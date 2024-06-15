#pragma once
#ifndef USER_HPP
#define USER_HPP

#include <string>
#include <vector>
#include <chrono>

class User {
    private:
        std::string mEmail;
        std::string mNickname;
        std::vector<uint8_t> mPassword;
        long long mCreationTime;

    public:
        User() : mEmail(""), mNickname(""), mPassword({}), mCreationTime(0) {}
        
        User(const std::string& email, const std::string& nickname, const std::vector<uint8_t>& password) : mEmail(email), mNickname(nickname), mPassword(password) {
            mCreationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
        }

        std::string getEmail() const { return mEmail; }
        std::string getNickname() const { return mNickname; }
        std::vector<uint8_t> getPassword() const { return mPassword; }
        long long getCreationTime() const { return mCreationTime; }
};

#endif