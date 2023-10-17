#include "Crc.h"


void Crc::generate_crc_table() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (uint32_t j = 8; j > 0; j--) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            }
            else {
                crc >>= 1;
            }
        }
        crc_table[i] = crc;
    }
}

uint32_t Crc::crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data) {
        uint8_t lookup = (crc ^ byte) & 0xFF;
        crc = (crc >> 8) ^ crc_table[lookup];
    }
    return ~crc;
}