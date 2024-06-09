#pragma once

#include <iostream>
#include <cstring>
#include <unistd.h>

#include "../../shared-libs/Packet.hpp"

void handle_client(int client_socket);