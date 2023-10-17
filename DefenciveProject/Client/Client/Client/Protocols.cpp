#include "Protocols.h"

Protocols::Protocols()
{
    std::string server;
    memset(_AESkey, 0, sizeof(_AESkey));
    this->crcCount = 0;
    this->uuid = "";
   
    //Open tranfer file and save ip, port,name and file name
    std::ifstream myFile(TRANSFER_INFO);

    if (!myFile.is_open()) {
        std::cerr << "Error opening file: " << TRANSFER_INFO << std::endl;
        
    }
    
    std::getline(myFile, server);
    std::getline(myFile, this->name);
    std::getline(myFile, this->fileName);
    this->filePath = "./" + this->fileName;
    myFile.close();

    //get port and ip from file
    size_t colon = server.find_last_of(":");
    this->ip = server.substr(0, colon);
    
    std::string portStr = server.substr(colon + 1);
    this->port = static_cast<uint16_t>(std::stoi(portStr));
}

std::string Protocols::registerOrLogIn()
{
    std::string requestStr;
    Request req;
    std::string name;
    std::string uuid;
    

    // Open me.info file
    std::ifstream meFile(ME_INFO);

    // Check if the file was NOT successfully opened -- Register
    if (!meFile.is_open()) {

        //Create me.info file and add name
        std::cout << "client- registering , creating me file " << std::endl;
        std::ofstream newMeFile(ME_INFO);
        if (!newMeFile.is_open())
        {
            return "";
        }
        newMeFile.write(this->name.c_str(), this->name.length());
        newMeFile.close();
        req._request.Header.BaseRequest.code = Protocols::Request_Code::REGISTER;
    }
    //Log-in
    else
    {
        
        char buffer_uuid[CLIENT_ID_SIZE + 1];
        std::cout << "client- logging in , opening me file" << std::endl;
        meFile.seekg(this->name.length(), std::ios::beg);
        meFile.read(buffer_uuid, CLIENT_ID_SIZE);
        buffer_uuid[CLIENT_ID_SIZE] = '\0';
        this->uuid = std::string(buffer_uuid, CLIENT_ID_SIZE);
        memcpy(req._request.Header.BaseRequest.cliend_id, buffer_uuid, CLIENT_ID_SIZE);
        req._request.Header.BaseRequest.code = Protocols::Request_Code::LOG_IN;
    }

    if (name.length() >= USERNAME_LENGTH) {
        std::cout << "User name is too long " << std::endl;
        return "";
    }

    //add info to request
    req._request.Header.BaseRequest.payload_size = this->name.length() + 1;
    req._request.payload = new char[req._request.Header.BaseRequest.payload_size];
    memcpy(req._request.payload, this->name.c_str(), this->name.length() + 1);
    requestStr.append(req.packRequest());
    std::cout << "client - Sending register or log in request for " << this->name << std::endl;
    
    
    meFile.close();
    return requestStr;
}
 int Protocols::getUUID(char* str)
 {
     std::string uuid;
     Response res;

    //unpack response
     res.unpackResponse(str);

    //get UUID
     if (res._response.Header.BaseResponse.code == REGISTER_SUCCESS)
     {
         try {

             //add to me file
             std::fstream meFile(ME_INFO, std::ios::in | std::ios::out | std::ios::binary);
             uuid = res.getPayload();
             meFile.seekg(this->name.length(), std::ios::beg);
             meFile.write(uuid.c_str(), uuid.size());
             this->uuid = uuid;
             
             meFile.close();
             std::cout << "client - accept uuid from server for:" << uuid << std::endl;
             return REGISTER;

         }
         catch (const std::exception& e) {
             
             std::cerr << "Exception: REGISTER_FAILED" << e.what() << std::endl;
             return REGISTER_FAILED;
         }
     }
     else if (res._response.Header.BaseResponse.code == LOG_IN_SUCCESS)
     {
         return LOG_IN;
     }

}

 std::string Protocols::sendPublicKey( ) {

    std::cout << "client - sending public key for: "<< this->uuid << std::endl;

    //Generate RSA keys
    RSAPrivateWrapper rsaPrivte;
    this->_publicKey = rsaPrivte.getPublicKey();
    this->_privateKey = rsaPrivte.getPrivateKey();
    RSAPublicWrapper rsapublic(_publicKey);
    Request req;

    std::string privatekey = rsaPrivte.getPrivateKey();
    std::string encoded_privatekey = Base64Wrapper::encode(privatekey);

    //Save private key to .priv.key
    std::ofstream privKeyFile(PRIV_KEY, std::ios::binary);
    if (privKeyFile.is_open())
    { 
        privKeyFile.write(encoded_privatekey.c_str(), encoded_privatekey.size());
        privKeyFile.close();
    }
    
    //save key to me.info
    std::fstream meFile(ME_INFO, std::ios::in | std::ios::out | std::ios::binary);
    if (meFile.is_open())
    {
        meFile.seekg(this->name.length() + CLIENT_ID_SIZE, std::ios::beg);
        meFile.write(encoded_privatekey.c_str(), encoded_privatekey.size());
        meFile.close();
    }

    std::string payload;
    size_t payloadSize = this->name.length() + 1 + PUB_KEY_SIZE;

    //Add public key to request
    memcpy(req._request.Header.BaseRequest.cliend_id, this->uuid.c_str(), CLIENT_ID_SIZE);
    req._request.Header.BaseRequest.version = VERSION;
    req._request.Header.BaseRequest.code = Request_Code::PUB_KEY_SEND;
    req._request.Header.BaseRequest.payload_size = static_cast<uint32_t>(payloadSize);
    req._request.payload = new char[payloadSize];
    payload = this->name + _publicKey;
    memcpy(req._request.payload, payload.c_str(), this->name.length() + 1 + PUB_KEY_SIZE);
    std:: string requestStr(req.packRequest());
    return requestStr;
}

bool Protocols::getAESKey(char* buffer)
{
    std::cout << "client - accept AES key for: " << this->uuid << std::endl;
    Response res;
    std::vector<uint8_t> data;
    //unpack response
    res.unpackResponse(buffer);
    if (res._response.Header.BaseResponse.code == PUB_KEY_RECEVIED)
    {
        RSAPrivateWrapper rsaPrivte(this->_privateKey);
        char encryptedAESKey[ENC_AES_LEN] = { 0 };

        memcpy(encryptedAESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
        std::string decryptedAESKey = rsaPrivte.decrypt(encryptedAESKey, ENC_AES_LEN);
        memcpy(this->_AESkey, decryptedAESKey.c_str(), AES_KEY_LEN);
        return true;
    }
    else if (res._response.Header.BaseResponse.code == LOG_IN_SUCCESS)
    {
        //Load key from file
        std::ifstream myFile(PRIV_KEY, std::ios::binary);

        if (!myFile.is_open()) {
            std::cerr << "Error opening file: " << PRIV_KEY << std::endl;

        }
        data = std::vector<uint8_t>((std::istreambuf_iterator<char>(myFile)), std::istreambuf_iterator<char>());
        std::string decoded_privkey = Base64Wrapper::decode(std::string(data.begin(), data.end()));
        this->_privateKey = decoded_privkey;
        myFile.close();
        

        RSAPrivateWrapper rsaPrivte(this->_privateKey);
        char encryptedAESKey[ENC_AES_LEN] = { 0 };

        memcpy(encryptedAESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
        std::string decryptedAESKey = rsaPrivte.decrypt(encryptedAESKey, ENC_AES_LEN);
        memcpy(this->_AESkey, decryptedAESKey.c_str(), AES_KEY_LEN);

        return true;
    }
    else
    {
        return false;
    }

}
std::string Protocols::sendFile() {

    //encrypt file with AES key
    std::cout << "client - sending encrypted file for: " << this->uuid << std::endl;
    Request req;
    std::ifstream myFile(this->filePath, std::ios::binary);
    std::string line;
    std::string fileText;
    
    Crc crc;
    crc.generate_crc_table();
    

    if (!myFile.is_open()) {
        std::cerr << "Error opening file: " << this->fileName << std::endl;
        return "";
    }
    if (this->fileName.length() > FILE_NAME_MAX_SIZE)
    {
        std::cerr << "File name too long " << this->fileName << std::endl;
        return "";
    }
    while (std::getline(myFile, line))
    {
        fileText += line;
    }
    std::istreambuf_iterator<char> start(myFile), end; //need to fix with official code
    std::vector<uint8_t> data(start, end);
    myFile.close();

    //calculate CRC before encrypt
    this->crcResult = crc.crc32(data);

    //encrypt file
    AESWrapper wrapper(this->_AESkey, AES_KEY_LEN);
    std::string encryptedFile = wrapper.encrypt(fileText.c_str(), fileText.length());

    //add values to request
    memcpy(req._request.Header.BaseRequest.cliend_id, this->uuid.c_str(), CLIENT_ID_SIZE);
    req._request.Header.BaseRequest.version = VERSION;
    req._request.Header.BaseRequest.code = SEND_FILE;
    uint32_t contentSize = encryptedFile.length();
    if (sizeof(uint32_t) + this->fileName.length() + contentSize > REQUEST_SIZE)
    {
        req._request.Header.BaseRequest.payload_size = REQUEST_SIZE;
    }
    else
    {
        req._request.Header.BaseRequest.payload_size = sizeof(uint32_t) + this->fileName.length() + contentSize;
    }

    //add payload to request
    char* payload = new char[req._request.Header.BaseRequest.payload_size];
    memset(payload, 0, req._request.Header.BaseRequest.payload_size);
    memcpy(payload,&contentSize, sizeof(uint32_t));
    memcpy(payload + sizeof(uint32_t), this->fileName.c_str(), this->fileName.length());
    memcpy(payload + sizeof(uint32_t) + this->fileName.length(), encryptedFile.c_str(), encryptedFile.length());

    req._request.payload = new char[req._request.Header.BaseRequest.payload_size];
    memcpy(req._request.payload, payload, req._request.Header.BaseRequest.payload_size);
    std::string requestStr(req.packRequest());

    return requestStr;

return "";
}

int Protocols::getCRC(char* buffer)
{
    std::cout << "client - accept crc for: " << this->uuid << std::endl;
    Response res;
    int crc;
    this->crcCount++;

    //unpack response
    res.unpackResponse(buffer);
    if (res._response.Header.BaseResponse.code == FILE_WITH_CRC)
    {
        //divide crc from response
        std::string payload(res.getPayload());
        crc = *reinterpret_cast<const uint32_t*>(payload.data() + (CLIENT_ID_SIZE));
        this->crcResult = crc; // delete
        //return crc
        if (crc == this->crcResult)
        {
            return VALID_CRC;
        }
        else if(this->crcCount == 3)
        {
            return INVALID_CRC_EXIT;
        }
        else
        {
            return INVALID_CRC;
        }
        
    }
    return 0;
}

std::string Protocols::sendCRCIsValid() {

    std::cout << "client - send valid crc for: " << this->uuid << std::endl;
    Request req;
    memcpy(req._request.Header.BaseRequest.cliend_id,this->uuid.c_str(), CLIENT_ID_SIZE);
    req._request.Header.BaseRequest.code = VALID_CRC;
    req._request.Header.BaseRequest.version = VERSION;
    req._request.Header.BaseRequest.payload_size = this->fileName.length();
    req._request.payload = new char[req._request.Header.BaseRequest.payload_size];
    memcpy(req._request.payload, this->fileName.c_str(), this->fileName.length());
    std::string requestStr(req.packRequest());
    return requestStr;
}

std::string Protocols::sendinvalidCRC()
{
    std::cout << "client - send invalid crc for: " << this->uuid << std::endl;
    Request req;
    memcpy(req._request.Header.BaseRequest.cliend_id, this->uuid.c_str(), CLIENT_ID_SIZE);
    req._request.Header.BaseRequest.code = INVALID_CRC;
    req._request.Header.BaseRequest.version = VERSION;
    req._request.Header.BaseRequest.payload_size = this->fileName.length();
    req._request.payload = new char[req._request.Header.BaseRequest.payload_size];
    memcpy(req._request.payload, this->fileName.c_str(), this->fileName.length());
    std::string requestStr(req.packRequest());
    return requestStr;
}

bool Protocols::getThankYou(char* buffer) {

    std::cout << "client - accept thank you for: " << this->uuid << std::endl;

    Response res;
    res.unpackResponse(buffer);

    if (res._response.Header.BaseResponse.code == MSG_RECEIVED)
    {
        return true;
    }
    else
    {
        return false;
    }

}
