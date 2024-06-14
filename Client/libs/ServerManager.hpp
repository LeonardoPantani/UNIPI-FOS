#pragma once

#include "../../shared-libs/Packet.hpp"
#include "../../shared-libs/cryptomanager.hpp"
#include "AsyncInput.hpp"
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <map>
#include <vector>
#include <sstream>
#include <regex>
#include <csignal>
#include <cstdio>
#include <sys/socket.h>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#endif

enum Command {
    CMD_REGISTER,
    CMD_LOGIN,
    CMD_LIST,
    CMD_GET,
    CMD_ADD,
    CMD_HELP,
    CMD_UNKNOWN
};

Command getCommand(const std::string& command);
std::vector<std::string> splitInput(const std::string& input);
std::string readPassword();
bool isValidEmail(const std::string& email);
bool validateLength(const std::string& arg, size_t maxLength);

void handle_server(int server_socket, volatile sig_atomic_t &clientRunning);
void handle_user_input(int server_socket, volatile sig_atomic_t &clientRunning);
