#include "UUID.hpp"

namespace uuid {
    std::string generate_uuid_v4() {
        unsigned char uuid_bytes[16];

        // 16 byte casuali
        if (RAND_bytes(uuid_bytes, sizeof(uuid_bytes)) != 1) {
            throw std::runtime_error("Errore generazione del UUID.");
        }

        uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40; // ultimo byte rappresenta v4
        uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80; // ultimo byte rappresenta variant 1

        // conversione byte in UUID4
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 16; ++i) {
            ss << std::setw(2) << static_cast<int>(uuid_bytes[i]);
            if (i == 3 || i == 5 || i == 7 || i == 9) {
                ss << '-';
            }
        }
        return ss.str();
    }
}