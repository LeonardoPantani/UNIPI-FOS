#pragma once
#ifndef SERVERMANAGER_HPP
#define SERVERMANAGER_HPP

#include <iostream>
#include <cstring>
#include <map>
#include <vector>
#include <csignal>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <regex>
#include <string>
#include <iterator>

#include "../../shared-libs/json.hpp"
#include "../../shared-libs/Packet.hpp"
#include "../../shared-libs/Utils.hpp"

#include "CryptoClient.hpp"
#include "AsyncInput.hpp"

enum Command {
    CMD_REGISTER,
    CMD_LOGIN,
    CMD_LOGOUT,
    CMD_LIST,
    CMD_GET,
    CMD_ADD,
    CMD_HELP,
    CMD_UNKNOWN
};

Command getCommand(const std::string& command);
std::tuple<std::string, std::string, std::string> addMessageCommandParser(const std::string& input);

void handle_server(int server_socket, volatile sig_atomic_t &clientRunning);
void handle_user_input(int server_socket, volatile sig_atomic_t &clientRunning);

#endif