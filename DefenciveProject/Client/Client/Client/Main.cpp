#include <iostream>
#include <boost/asio.hpp>
#include <fstream>
#include <cstdarg>
#include <filesystem>   
#include "Protocols.h"

#define PACKET_SIZE 1024
using boost::asio::ip::tcp;

int main() {

    std::string myRequest;
    char* myResponse = new char[PACKET_SIZE];
    
    //Connecting to server
    boost::asio::io_service io_service;
    tcp::socket socket(io_service);
   
    Protocols protocol;
    
    try {

        
        // Define the server endpoint
        boost::asio::ip::tcp::endpoint server_endpoint(boost::asio::ip::address::from_string(protocol.ip), protocol.port);
        
        // Connect to the server
        socket.connect(server_endpoint);
        
        // Send data to the server ---------------Register or log-in
        myRequest = protocol.registerOrLogIn();
        if (myRequest.empty())
        {
            exit(1);
        }
        
        boost::asio::write(socket, boost::asio::buffer(myRequest));
        
        //Get Response from server ---------- UUID or AES key(in case of log in)
        boost::system::error_code error;
        size_t bytesRead = socket.read_some(boost::asio::buffer(myResponse , PACKET_SIZE), error);

        //unpack response
        int registerResponseCode = protocol.getUUID(myResponse);
        if (registerResponseCode == Protocols::REGISTER)
        {
            //Send request to server -------------public key (only if not log in)
            myRequest = protocol.sendPublicKey();
            if (!myRequest.empty())
            {
                boost::asio::write(socket, boost::asio::buffer(myRequest));
                //Get Response from server ------- AES key
                bytesRead = socket.read_some(boost::asio::buffer(myResponse, PACKET_SIZE), error);
            }
        }
        else if (registerResponseCode == Protocols::REGISTER_FAILED)
        {
            exit(1);
        }
        
        //unpack response
       if (!protocol.getAESKey(myResponse))
        {
            exit(1);
        }
    
        int crc = 0;
        while (crc != protocol.INVALID_CRC_EXIT && crc != protocol.VALID_CRC)
        {
            if (crc != 0)
            {
                myRequest = protocol.sendinvalidCRC();
                if (myRequest.empty())
                {
                    exit(1);
                }
                //send invalid crc
                boost::asio::write(socket, boost::asio::buffer(myRequest));

                //Get Response from server ------- confirm
                bytesRead = socket.read_some(boost::asio::buffer(myResponse, PACKET_SIZE), error);
                if (!protocol.getThankYou(myResponse))
                {
                    exit(1);
                }


            }
            //Send request to server ------------- encrypted file
            myRequest = protocol.sendFile();
            if (myRequest.empty())
            {
                exit(1);
            }
            //send encrypted file
            boost::asio::write(socket, boost::asio::buffer(myRequest));

            //Get Response from server ------- CRC
            bytesRead = socket.read_some(boost::asio::buffer(myResponse , PACKET_SIZE), error);

            //unpack response
            crc = protocol.getCRC(myResponse);

        }
        //check if crc is valid
        if (crc != protocol.VALID_CRC)
        {
            socket.close();
            exit(1);
            
        }
         //send request ----------- CRC VALID
        myRequest = protocol.sendCRCIsValid();
        if (myRequest.empty())
        {
            std::cout << "crc not valid for 3 tries. closing connection" << std::endl;
            socket.close();
            exit(1);
        }
        boost::asio::write(socket, boost::asio::buffer(myRequest));
       
        //get response --------- ok , thank you
        bytesRead = socket.read_some(boost::asio::buffer(myResponse , PACKET_SIZE), error);

        //unpack response
        if (!protocol.getThankYou(myResponse))
        {
            std::cout << "session ended successfully. closing connection" << std::endl;
            socket.close();
            exit(1);
        }
        
        if (error == boost::asio::error::eof) {
            // Connection closed by the server
            std::cout << "Connection closed by the server." << std::endl;
        }
        else if (error) {
            // Handle error
            throw boost::system::system_error(error);
        }

    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    socket.close();
    return 0;
}
