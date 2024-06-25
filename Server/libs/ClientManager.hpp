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
#include "CryptoServer.hpp"
#include "PersistentMemory.hpp"
#include "User.hpp"

// variabili dal main
extern PersistentMemory* memory;
extern CryptoServer* crypto;
extern volatile std::atomic<bool> serverRunning;
extern volatile std::atomic<int> activeConnections;

/// @brief Funzione principale eseguita in un thread che gestisce un singolo client.
/// @param client_socket il descrittore del socket a cui il client è connesso
void handle_client(int client_socket);

#endif