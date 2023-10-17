#ifndef REQUEST_H
#define REQUEST_H

#pragma once
#include <iostream>
#include <stdint.h>

#define REQUEST_SIZE 1024
#define CLIENT_ID_SIZE 16
#define VERSION 3
class Request {
	friend class Protocols;
public:
#pragma pack(push, 1)
	struct RequestFormat {
		union Header {
			struct BaseRequest {
				char cliend_id[CLIENT_ID_SIZE];
				uint8_t version;
				uint16_t code;
				uint32_t payload_size;
			} BaseRequest;
			char buffer[sizeof(BaseRequest)];
		} Header;
		char* payload;
	} _request;
#pragma pack(pop)
	
	std::string packRequest();
	uint32_t requestSizeLeft() const;
	const char* getPayload() const;
	Request();
	~Request();

};
#endif  // REQUEST_H

