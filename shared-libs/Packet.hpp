#pragma once
#include <vector>
#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>

enum class PacketType {
    HELLO,             /* sent as first communication */
    BYE,               /* sent by client on connection closing */
    SERVER_FULL,       /* sent by server when it is full */
    SERVER_CLOSING,    /* sent by server when is getting terminated */
    LOGIN_REQUEST,     /* sent by client to request login */
    REGISTER_REQUEST,  /* sent by client to request register */
    LOGIN_OK,          /* sent by server to answer login request */
    REGISTER_OK,       /* sent by server to answer register request */
    ERROR,             /* error */
    OTHER,             /* generic */
    BBS_LIST,          /* command list */
    BBS_GET,           /* command get */
    BBS_ADD            /* command add */
};

const size_t DATA_SIZE = 101; // includes the \0 character, so the limit of writable characters is DATA_SIZE-1
const size_t PACKET_SIZE = sizeof(PacketType) + DATA_SIZE;


struct Packet {
    PacketType type;
    std::vector<char> data;

    // Constructor that only accepts the package type (i.e. for HELLO packets)
    Packet(PacketType type) : type(type) {
        data.resize(DATA_SIZE, 0);
    }

    // Constructor accepting packet type and data
    Packet(PacketType type, const std::string& content): type(type), data(content.begin(), content.end()) {
        if (data.size() > DATA_SIZE) {
            throw std::runtime_error("Content size exceeds the limit of " + std::to_string(DATA_SIZE - 1) + " characters.");
        } else {
            data.resize(DATA_SIZE, 0); // Padding with zeroes to ensure fixed size
        }
    }

    Packet(const char* buffer, size_t size) {
        if (size != PACKET_SIZE) {
            throw std::runtime_error("Buffer size is invalid.");
        }
        type = static_cast<PacketType>(*buffer);
        data.insert(data.end(), buffer + sizeof(PacketType), buffer + size);
    }

    std::vector<char> serialize() const {
        std::vector<char> serialized(PACKET_SIZE);
        serialized[0] = static_cast<char>(type);
        std::memcpy(serialized.data() + sizeof(PacketType), data.data(), DATA_SIZE);
        return serialized;
    }

    static Packet deserialize(const char* buffer, size_t size) {
        return Packet(buffer, size);
    }

    std::string getContent() const {
        return std::string(data.begin(), data.end());
    }

    std::string getTypeAsString() const {
        switch (type) {
            case PacketType::HELLO: return "HELLO";
            case PacketType::BYE: return "BYE";
            case PacketType::SERVER_FULL: return "SERVER_FULL";
            case PacketType::SERVER_CLOSING: return "SERVER_CLOSING";
            case PacketType::LOGIN_REQUEST: return "LOGIN_REQUEST";
            case PacketType::REGISTER_REQUEST: return "REGISTER_REQUEST";
            case PacketType::LOGIN_OK: return "LOGIN_OK";
            case PacketType::REGISTER_OK: return "REGISTER_OK";
            case PacketType::ERROR: return "ERROR";
            case PacketType::OTHER: return "OTHER";
            case PacketType::BBS_LIST: return "BBS_LIST";
            case PacketType::BBS_GET: return "BBS_GET";
            case PacketType::BBS_ADD: return "BBS_ADD";
            default: return "UNKNOWN";
        }
    }
};
