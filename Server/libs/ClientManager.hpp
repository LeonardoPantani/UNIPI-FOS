#pragma once

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <cstring>
#include <thread>

#include "../../shared-libs/Packet.hpp"
#include "PersistentMemory.hpp"

void handle_client(int client_socket, std::thread::id threadId);