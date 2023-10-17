#ifndef RESPONSE_H
#define RESPONSE_H

#pragma once
#include <iostream>
#include <stdint.h>

#define RESPONSE_SIZE 1024
#define VERSION 3

class Response {
	friend class Protocols;
public:
#pragma pack(push, 1)
	struct ResponseFormat {
		union Header {
			struct BaseResponse {
				uint8_t version;
				uint16_t code;
				uint32_t payload_size;
			} BaseResponse;
			char buffer[sizeof(BaseResponse)];
		} Header;
		char* payload;
	} _response;
#pragma pack(pop)

	void unpackResponse(char*);
	std::string getPayload() ;
	uint32_t responseSizeLeft() const;
	Response();
	~Response();
};
#endif  // RESPONSE_H

#pragma once
