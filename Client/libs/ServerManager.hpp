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

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#endif

void handle_server(int server_socket);
