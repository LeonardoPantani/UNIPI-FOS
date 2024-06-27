#pragma once
#ifndef UUID_HPP
#define UUID_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/rand.h>

namespace uuid {
    std::string generate_uuid_v4();
}

#endif