#pragma once
#ifndef CLIENTMANAGER_HPP
#define CLIENTMANAGER_HPP

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <thread>
#include <atomic>
#include <sys/select.h>

#include "../../shared-libs/Packet.hpp"
#include "../../shared-libs/Utils.hpp"
#include "PersistentMemory.hpp"

void handle_client(int client_socket);

#endif