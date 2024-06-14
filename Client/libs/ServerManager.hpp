#pragma once

#include "../../shared-libs/Packet.hpp"
#include "../../shared-libs/cryptomanager.hpp"
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <map>
#include <vector>
#include <sstream>
#include <regex>
#include <csignal>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#endif

void handle_server(int server_socket, volatile sig_atomic_t keepRunning);
