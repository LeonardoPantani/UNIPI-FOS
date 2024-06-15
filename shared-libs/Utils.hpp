#pragma once
#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <regex>
#include <unistd.h>
#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#endif

std::vector<std::string> splitInput(const std::string& input);
std::string readPassword();
bool isValidEmail(const std::string& email);
bool validateLength(const std::string& arg, size_t maxLength);

#endif