#pragma once

#include <string>
#include <vector>
#include <chrono>

class User {
    private:
        std::string email;
        std::string nickname;
        std::vector<uint8_t> password;
        long long creationTime;

    public:
        User() : email(""), nickname(""), password({}) {} // Costruttore di default
        
        User(const std::string& email, const std::string& nickname, const std::vector<uint8_t>& password) {
            this->email = email;
            this->nickname = nickname;
            this->password = password;
            creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count();
        }

        std::string getEmail() const { return email; }
        std::string getNickname() const { return nickname; }
        std::vector<uint8_t> getPassword() const { return password; }
        long long getCreationTime() const { return creationTime; }
};

