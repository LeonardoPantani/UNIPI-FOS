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
#include <mutex>
#include <algorithm>

#include "../../shared-libs/Packet.hpp"
#include "../../shared-libs/Utils.hpp"
#include "PersistentMemory.hpp"
#include "User.hpp"

void addAuthUser(const std::string& nickname);
void removeAuthUser(const std::string& nickname);
bool isUserAuthenticated(const std::string& nickname);

std::string generateVerificationCode();

void handle_client(int client_socket);

#endif