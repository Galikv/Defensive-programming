#pragma once
#include <vector>
#include <cstdint>


class Crc {

public:
	uint32_t crc_table[256];

	void generate_crc_table();
	uint32_t crc32(const std::vector<uint8_t>& data);
};