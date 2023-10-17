#include "encryption.h"


bool Encryption::generateKeys() {
	std::cout << "in generateKeys" << std::endl;

	RSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(_rng, KEY_SIZE);

	RSA::PublicKey publicKey(privateKey);
	_privateKey = privateKey;
	_publicKey = publicKey;
	/*_privateKey.Initialize(_rng, KEY_SIZE);

	// With the current version of Crypto++, MessageEnd() needs to be called
	// explicitly because Base64Encoder doesn't flush its buffer on destruction.
	Base64Encoder privkeysink(new FileSink("privkey.txt"));
	_privateKey.DEREncode(privkeysink);
	privkeysink.MessageEnd();

	// Suppose we want to store the public key separately,
	// possibly because we will be sending the public key to a third party.
	RSAFunction pubkey(_privateKey);

	Base64Encoder pubkeysink(new FileSink("pubkey.txt"));
	pubkey.DEREncode(pubkeysink);
	pubkeysink.MessageEnd();*/



	/*InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(_rng, KEY_SIZE);
	_publicKey.Initialize(params.GetModulus(), params.GetPublicExponent());
	_privateKey.Initialize(params.GetModulus(), params.GetPublicExponent(), params.GetPrivateExponent());*/
	
	/*_privateKey.GenerateRandomWithKeySize(_rng, KEY_SIZE);
	CryptoPP::RSA::PublicKey _publicKey(_privateKey);

	FileSink privateFile(".priv.key");
	_privateKey.Save(privateFile);

	FileSink publicFile(".public.key");
	_publicKey.Save(publicFile);*/

	//SaveKey("priv", _privateKey);
	//SaveKey("pub", _publiceKey);

	//Generate RSA keys
	/*InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(_rng, KEY_SIZE);
	_privateKey = RSA::PrivateKey(params);
	_publicKey = RSA::PublicKey(params);

	FileSink privateFile(".priv.key");
	_privateKey.Save(privateFile);

	FileSink publicFile("public_key.pem");
	_publicKey.Save(publicFile);*/



	/*_privateKey.Initialize(rng, KEY_SIZE);
	RSAFunction publicKey(_privateKey);
	std::string key;
	StringSink sink(key);
	publicKey.Save(sink);
	StringSource source(key, true);
	_publicKey.Load(source);*/

	return true; //// fix
}
/*bool Encryption::checkKeys()
{
	if (_privateKey.Validate(_rng, 3) && _publicKey.Validate(_rng, 3)) {
		std::cout << "RSA keys are valid." << std::endl;
		std::cout << "Private Key Modulus Size: " << _privateKey.GetModulus().BitCount() << " bits" << std::endl;
		std::cout << "Public Key Modulus Size: " << _publicKey.GetModulus().BitCount() << " bits" << std::endl;
		return true;
	}
	else {
		std::cerr << "RSA keys are not valid." << std::endl;
		return false;
	}
}*/
std::string Encryption::getPublicKey() {

	RSAFunction _publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	_publicKey.Save(ss);
	return key;
}

std::string Encryption::getPrivateKey() {

	std::string privateKeyString;
	StringSink sink(privateKeyString);
	_privateKey.Save(sink);
	return privateKeyString;
}
/*bool Encryption::encryptFile(const std::string& inputFile, const std::string& outputFile, const byte* aesKey, size_t aesKeySize) {
	try {
		byte iv[AES::BLOCKSIZE] = { 0 }; // Initialize IV to all zeros

		// Create an AES encryption object using the provided AES key
		AES::Encryption aesEncryption(aesKey, aesKeySize);

		FileSource source(inputFile.c_str(), true,
			new StreamTransformationFilter(aesEncryption,
				new FileSink(outputFile.c_str()),
				new ArraySink(iv, sizeof(iv))
			)
		);

		return true;
	}
	catch (const Exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return false;
	}
}
*/

bool Encryption::updateAESKey(const char* newAESKey, size_t keySize) {
	try {
		if (keySize != AES::DEFAULT_KEYLENGTH) {
			std::cerr << "Invalid AES key size." << std::endl;
			return false;
		}

		aesKey.Assign(reinterpret_cast<const byte*>(newAESKey), keySize);
		return true;
	}
	catch (const Exception& e) {
		std::cerr << "Error updating AES key: " << e.what() << std::endl;
		return false;
	}
}
/*
bool Encryption::loadKeysFromFile() {
	try {
		FileSource source(PRIV_KEY, true);
		_privateKey.Load(source);
		publicKey.AssignFrom(privateKey);

		return true;
	}
	catch (const Exception& e) {
		std::cerr << "Error loading keys from file: " << e.what() << std::endl;
		return false;
	}
}*/
bool Encryption::saveKeysToFile() {
	std::cout << "in saveKeysToFile" << std::endl;
	try {
		std::ofstream file(PRIV_KEY, std::ios::binary);

		if (!file) {
			std::cerr << "Error opening file for writing: " << PRIV_KEY << std::endl;
			return false;
		}

		FileSink fileSink(file);
		_privateKey.Save(fileSink);

		std::cout << "keys saved in file succsesfully" << std::endl;

		return true;
	}
	catch (const Exception& e) {
		std::cerr << "Error saving keys to file: " << e.what() << std::endl;
		return false;
	}
}
std::string Encryption::decryptWithPrivateKey(std::string cipher, unsigned int length)
{

	//FileSource privFile(".priv.key", true, new HexDecoder);
	std::string Decrypted;
	try {
		
		RSAES_OAEP_SHA_Decryptor d(_privateKey);
		StringSource ss_cipher(cipher, true, new HexEncoder(new PK_DecryptorFilter(_rng, d ,new StringSink(Decrypted))));
	}
	catch (const CryptoPP::Exception& e) {
 		std::cerr << "Crypto++ exception: " << e.what() << std::endl;
		return "";
	}

	return Decrypted;
}



