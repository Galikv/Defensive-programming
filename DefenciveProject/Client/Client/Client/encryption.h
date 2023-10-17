#pragma once

#include <string>
#include <fstream>
#include <iostream>
#include <rsa.h>
#include <base64.h>
#include <pssr.h>
#include <filters.h>
#include <osrng.h>
#include <cryptlib.h>
#include <files.h>
#include <hex.h>
#define AES_KEY_LEN 16
#define KEY_SIZE 1024
#define PRIV_KEY  ".priv.key"
using namespace CryptoPP;

class Encryption {

public:
	AutoSeededRandomPool _rng;
	bool generateKeys();
	bool checkKeys();
	bool updateAESKey(const char*, size_t);
	bool loadKeysFromFile();
	bool saveKeysToFile();
	std::string decryptWithPrivateKey(std::string, unsigned int);
	std::string getPublicKey();
	std::string getPrivateKey();
	bool encryptFile(const std::string&, const std::string&, const byte*, size_t);

private:
	
	//RSA::PrivateKey _privateKey;
	//RSA::PublicKey _publicKey;
	RSA::PrivateKey _privateKey;
	RSA::PublicKey _publicKey;
	SecByteBlock aesKey;
};