
#pragma once
#include <WinSock2.h>
#include <Windows.h>

#include <string>
#include <fstream>
#include "Request.h"
#include "Response.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "Crc.h"

#pragma comment(lib, "ws2_32.lib")


#define REQUEST_SIZE 1024
#define USERNAME_LENGTH 127
#define ME_INFO "./me.info"
#define TRANSFER_INFO "./transfer.info"
#define PRIV_KEY "./.priv.key"
#define PUB_KEY_SIZE 160
#define AES_KEY_LEN 16
#define AES_BLOCK_SIZE 16
#define CLIENT_ID_SIZE 16
#define UINT32_SIZE 8
#define FILE_NAME_MAX_SIZE 255
#define TRANSFER_LINES 3
#define ENC_AES_LEN 128
#define MAX_TRIES 3

class Protocols {

public:
	std::string name;
	std::string fileName;
	std::string filePath;
	std::string ip;
	uint16_t port;
	std::string uuid;
	std::string _publicKey;
	std::string _privateKey;
	unsigned char _AESkey[AES_KEY_LEN];
	uint32_t crc_table[256];
	uint32_t crcResult;
	int crcCount;

	enum Request_Code { REGISTER = 1025, PUB_KEY_SEND = 1026, LOG_IN = 1027, SEND_FILE = 1028, VALID_CRC = 1029, INVALID_CRC = 1030, INVALID_CRC_EXIT = 1031 };
	enum Response_Code { REGISTER_SUCCESS = 2100, REGISTER_FAILED = 2101, PUB_KEY_RECEVIED = 2102, FILE_WITH_CRC = 2103, MSG_RECEIVED = 2104, LOG_IN_SUCCESS = 2105, LOG_IN_FAILED = 2106, UNKNOWN_FAIL = 2107 };
	Protocols();
//	~Protocols();
	std::string registerOrLogIn();
	std::string sendPublicKey();
	std::string sendFile();
	std::string sendCRCIsValid();
	std::string sendinvalidCRC();
	int getUUID(char*);
	bool getAESKey(char*);
	int getCRC(char*);
	bool getThankYou(char*);

};