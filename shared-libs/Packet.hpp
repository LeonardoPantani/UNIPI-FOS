#pragma once
#ifndef PACKET_HPP
#define PACKET_HPP

#include <vector>
#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <algorithm>

enum PacketType {
    HELLO,             /* sent by server (request) and client (answer): first communication */
    HANDSHAKE,
    HANDSHAKE_FINAL,
    BYE,               /* sent by client: on connection closing */
    SERVER_FULL,       /* sent by server: when it is full */
    SERVER_CLOSING,    /* sent by server: when is getting terminated */
    LOGIN_REQUEST,     /* sent by client: to request login */
    LOGIN_OK,          /* sent by server: to answer login request */
    REGISTER_REQUEST,  /* sent by client: to request register */
    REGISTER_CHECK,    /* sent by server (request) and client (answer): to verify email */
    REGISTER_OK,       /* sent by server: to answer register request */
    LOGOUT_REQUEST,    /* sent by client: to request logout */
    LOGOUT_OK,         /* sent by server: to answer logout request */
    ERROR,             /* sent by client & server: error */
    BBS_LIST,          /* sent by client (request) and server (answer): command list */
    BBS_GET,           /* sent by client (request) and server (answer): command get */
    BBS_ADD            /* sent by client (request) and server (answer): command add */
};

const size_t MAX_DATA_SIZE = 4096;
const size_t MAX_PACKET_SIZE = sizeof(PacketType) + MAX_DATA_SIZE;

struct Packet {
    PacketType mType;
    std::vector<char> mData;

    Packet() {
        
    }

    // Constructor that only accepts the package type
    Packet(PacketType packet_type) : mType(packet_type) {
        
    }

    // Constructor accepting packet type and data as "std::string"
    Packet(PacketType packet_type, const std::string& content): mType(packet_type), mData(content.begin(), content.end()) {
        if (mData.size() > MAX_DATA_SIZE) {
            throw std::runtime_error("Content size exceeds the limit of " + std::to_string(MAX_PACKET_SIZE) + " characters.");
        }
    }

    // Constructor accepting packet type and data as "char* data"
    Packet(PacketType packet_type, const unsigned char* data_input, size_t data_len): mType(packet_type) {
        std::memcpy(mData.data(), data_input, data_len);
    }

    // Constructor accepting buffer with size check
    Packet(const char* buffer, ssize_t size) {
        mType = static_cast<PacketType>(*buffer);
        mData.insert(mData.end(), buffer + sizeof(PacketType), buffer + size);
    }

    std::vector<char> serialize() const {
        std::vector<char> serialized(sizeof(PacketType) + mData.size());
        serialized[0] = static_cast<char>(mType);
        std::memcpy(serialized.data() + sizeof(PacketType), mData.data(), mData.size());
        return serialized;
    }

    static Packet deserialize(const char* buffer, ssize_t size) {
        return Packet(buffer, size);
    }

    std::string getContent() const {
        std::string toRet(mData.data(), mData.size());
        return toRet;
    }

    std::string getTypeAsString() const {
        switch (mType) {
            case PacketType::HELLO: return "HELLO";
            case PacketType::HANDSHAKE: return "HANDSHAKE";
            case PacketType::HANDSHAKE_FINAL: return "HANDSHAKE_FINAL";
            case PacketType::BYE: return "BYE";
            case PacketType::SERVER_FULL: return "SERVER_FULL";
            case PacketType::SERVER_CLOSING: return "SERVER_CLOSING";
            case PacketType::LOGIN_REQUEST: return "LOGIN_REQUEST";
            case PacketType::REGISTER_REQUEST: return "REGISTER_REQUEST";
            case PacketType::REGISTER_CHECK: return "REGISTER_CHECK";
            case PacketType::LOGIN_OK: return "LOGIN_OK";
            case PacketType::REGISTER_OK: return "REGISTER_OK";
            case PacketType::LOGOUT_REQUEST: return "LOGOUT_REQUEST";
            case PacketType::LOGOUT_OK: return "LOGOUT_OK";
            case PacketType::ERROR: return "ERROR";
            case PacketType::BBS_LIST: return "BBS_LIST";
            case PacketType::BBS_GET: return "BBS_GET";
            case PacketType::BBS_ADD: return "BBS_ADD";
            default: return "UNKNOWN";
        }
    }
};

#endif