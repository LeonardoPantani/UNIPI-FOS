#pragma once
#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <regex>
#include <unistd.h>

std::vector<std::string> splitInput(const std::string& input);
bool isValidEmail(const std::string& email);
bool validateLength(const std::string& arg, size_t maxLength);
bool isValidUUID(const std::string& uuid);

#endif