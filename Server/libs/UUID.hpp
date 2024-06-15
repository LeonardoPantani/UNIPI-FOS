#pragma once
#ifndef UUID_HPP
#define UUID_HPP

#include <string>
#include <random>
#include <sstream>

namespace uuid {
    std::string generate_uuid_v4();
}

#endif