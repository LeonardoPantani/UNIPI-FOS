#pragma once
#ifndef UTILS_HPP
#define UTILS_HPP

#include <unistd.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <regex>
#include <random>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <openssl/rand.h>

/// @brief Esegue l'istruzione write. Se dà errore, stampa su std::cerr
/// @param socket il socket su cui scrivere
/// @param toSend il dato da scrivere sul socket
#define WRITE(socket, toSend) \
    if (write(socket, toSend.data(), toSend.size()) == -1) { \
        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl; \
    }

/// @brief Esegue l'istruzione write. Se dà errore, stampa su std::cerr e esegue break
/// @param socket il socket su cui scrivere
/// @param toSend il dato da scrivere sul socket
#define WRITEB(socket, toSend) \
    if (write(socket, toSend.data(), toSend.size()) == -1) { \
        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl; \
        break; \
    }

/// @brief Esegue l'istruzione write. Se dà errore, stampa su std::cerr e lancia runtime error
/// @param socket   il socket su cui scrivere
/// @param toSend   il dato da scrivere sul socket
/// @param errorMsg il messaggio da mettere nel runtime_error
#define WRITET(socket, toSend, errorMsg) \
    if (write(socket, toSend.data(), toSend.size()) == -1) { \
        std::cerr << "[!] Errore nella scrittura sul socket." << std::endl; \
        throw std::runtime_error(errorMsg); \
    }

long generateRandomLong();
std::string generateVerificationCode(size_t digitsToGenerate);
std::vector<std::string> splitInput(const std::string& input);
bool isValidEmail(const std::string& email);
bool validateLength(const std::string& arg, size_t maxLength);
bool isValidUUID(const std::string& uuid);

std::string base64_encode(const std::vector<char>& input);
std::vector<char> base64_decode(const std::string &encoded);

/// @brief Sovrascrive tutta l'area di memoria riservata a toOverwrite
/// @param toOverwrite la variabile da sovrascrivere
void overwriteSecret(std::string &toOverwrite);

#endif