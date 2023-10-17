
import socket
import struct
from Request import Request
from Response import Response
from Database import Database
import uuid
import binascii
import os
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64
import threading
import math

#const size
CLIENT_ID_SIZE = 16
PUB_KEY_LEN = 160
CONTENT_SIZE = 4
CRC_SIZE = 4
AES_KEY_SIZE = 16
PACKET_SIZE = 1024
MAX_FILE_SIZE = 255



#from client
REGISTER = 1025
PUB_KEY_SEND = 1026
LOG_IN = 1027
SEND_FILE = 1028
VALID_CRC = 1029
INVALID_CRC = 1030
INVALID_CRC_EXIT = 1031 

#to Client
REGISTER_SUCCESS = 2100
REGISTER_FAILED = 2101
PUB_KEY_RECEVIED = 2102
FILE_WITH_CRC = 2103
MSG_RECEIVED = 2104
LOG_IN_SUCCESS = 2105
LOG_IN_FAILED = 2106
UNKNOWN_FAIL = 2107


def getResponse(data):

    myRequest = Request()
    myRequest.unpack(data)
    
    if myRequest.code == REGISTER or myRequest.code == LOG_IN:
        return registerOrLongInRequest(myRequest)
    elif myRequest.code == PUB_KEY_SEND:
        return sendAESkey(myRequest)
    elif myRequest.code == SEND_FILE:
        return sendCRC(myRequest)
    elif myRequest.code == VALID_CRC or myRequest.code == INVALID_CRC or myRequest.code == INVALID_CRC_EXIT:
        return sendThankYou(myRequest)
    else:
        return sendUnKnowmFail(myRequest)
  

def registerOrLongInRequest(myRequest):

    myResponse = Response()
    
    #get name from request
    username = myRequest.payload.decode('utf-8')
    isExsists = mydatabase.ifExsistsByName(username)

   #get id from request
    if myRequest.code == REGISTER:
        if not isExsists:
            #generate id
             myResponse.code = REGISTER_SUCCESS
             #add user to dataBase
             id = bytes.fromhex(uuid.uuid4().hex)
             mydatabase.Register(id , username)
             myResponse.payloadSize = CLIENT_ID_SIZE
             myResponse.payload = id
             print(f"server- Register success for: {id}")
        else:
            myResponse.code = REGISTER_FAILED
            print(f"server- Register failed for: {username}")

    elif myRequest.code == LOG_IN:
        if isExsists:
            myResponse.code = LOG_IN_SUCCESS
            #get id from database
            id = mydatabase.getIdByName(username)
            if not id:
                return sendUnKnowmFail(myRequest)
            myRequest.uuid=id
            #get public key from database
            encrypted_key = generateAESKey(mydatabase.getPublicKey(id),id)
            myResponse.payloadSize = CLIENT_ID_SIZE + len(encrypted_key)
            myResponse.payload = id + encrypted_key
            print(f"server- Log-in success for: {id}")

        else:
             myResponse.code = LOG_IN_FAILED
             print(f"server- log-in failed for: {username}")

    mydatabase.setLastSeen(id)
    return myResponse

def sendAESkey(myRequest):
    print(f"server- accept public key for: {myRequest.uuid}")
    myResponse = Response()
    mydatabase.setLastSeen(myRequest.uuid)
    #recive public key
    offset = myRequest.payloadSize - PUB_KEY_LEN - 1
    username = myRequest.payload[:offset].decode('utf-8')
    publicKey = myRequest.payload[offset:offset + PUB_KEY_LEN]
 
    #add public key to database
    mydatabase.addPublicKey(publicKey,myRequest.uuid)

    encrypted_key = generateAESKey(publicKey, myRequest.uuid)

    #send AES key
    myResponse.code = PUB_KEY_RECEVIED
    myResponse.payloadSize = CLIENT_ID_SIZE + len(encrypted_key) 
    myResponse.payload = myRequest.uuid + encrypted_key
    print(f"server- send AES key for: {myRequest.uuid}")
    return myResponse

def generateAESKey(publicKey, id):

    #generate AES key
    iv = bytes([0] * AES.block_size)
    aes_key = os.urandom(AES_KEY_SIZE)
  
    #encrypt AES with public key
    rsa_publickey = RSA.importKey(publicKey)
    cipher_rsa  = PKCS1_OAEP.new(rsa_publickey)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    #add AES to database
    mydatabase.addAESKey(base64.b64encode(aes_key).decode('utf-8'),id)

    return encrypted_key


def sendCRC(myRequest):
    print(f"server- accept file for: {myRequest.uuid}")
    myResponse = Response()
    mydatabase.setLastSeen(myRequest.uuid)

    #get file from request
    contentSize = myRequest.payload[:CONTENT_SIZE]
    contentSize = int.from_bytes(contentSize, byteorder='little')
    fileName = myRequest.payload[CONTENT_SIZE:myRequest.payloadSize -contentSize].decode('utf-8')
    msgContent = myRequest.payload[CONTENT_SIZE + len(fileName):myRequest.payloadSize]

    #decrypt file
    encoded_aes_key = mydatabase.getAESKey(myRequest.uuid)
    if not encoded_aes_key:
        return sendUnKnowmFail(myRequest)
    decoded_aes_key = base64.b64decode(encoded_aes_key)
    
    iv = b'\x00' * AES.block_size
    cipher = AES.new(decoded_aes_key, AES.MODE_CBC, iv)
    raw = cipher.decrypt(msgContent)
    decryptMsg = unpad(raw, AES.block_size)
 
    #calculate crc
    crc = crc32(decryptMsg)

    #save to database
    mydatabase.addFileName(myRequest.uuid, fileName)
    mydatabase.addCrc(myRequest.uuid, crc)
    path = "./Server/Server/Client/Client" 
    path += fileName
    mydatabase.addPath(myRequest.uuid, path)

    #add to response
    contentSizeBytes= calculateNumOfBytes(contentSize)
    myResponse.code = FILE_WITH_CRC
    myResponse.payloadSize = CLIENT_ID_SIZE + CRC_SIZE + len(fileName) + contentSizeBytes
    myResponse.payload = myRequest.uuid
    myResponse.payload += struct.pack('<I', crc)
    myResponse.payload += fileName.encode('utf-8') 
    myResponse.payload += contentSize.to_bytes(contentSizeBytes, byteorder='little')
    print(f"server- send crc for: {myRequest.uuid}")
    return myResponse


def calculateNumOfBytes(contentSize):
    count=0;
    while(contentSize > 1):
        contentSize = contentSize/4
        count = count + 1
      
    return math.ceil(count/2)


def crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF

def sendThankYou(myRequest):

    mydatabase.setLastSeen(myRequest.uuid)
    myResponse = Response()
    myResponse.code = MSG_RECEIVED
    myResponse.payloadSize = CLIENT_ID_SIZE
    myResponse.payload = myRequest.uuid
    print(f"server- send thank you for: {myRequest.uuid}")
    return myResponse

def sendUnKnowmFail(myRequest):

    myResponse = Response()
    myResponse.code = UNKNOWN_FAIL
    myResponse.payloadSize = 0
    myResponse.payload = ""
    print(f"server- send unknown fail for : {myRequest.uuid}")
    return myResponse


def handle_client(client_socket, address):
    with lock:
        while True:
            currResponse = Response()
            data = client_socket.recv(PACKET_SIZE)
            if not data:
                break
            currResponse = getResponse(data)
            currCode = currResponse.code
            packedResponse = currResponse.pack()
            client_socket.send(packedResponse)

            if currCode == VALID_CRC or currCode == INVALID_CRC_EXIT or currCode == UNKNOWN_FAIL:
                # end of session, close the client socket
                print("server- server cloesed")
                client_socket.close()
                break

lock = threading.Lock()
# Read the port number from a text file
try:
    with open("port.info", "r") as file:
        port = int(file.read())
except FileNotFoundError:
    # Use a default port if the file is not found
    port = 1357

#Create or load database
mydatabase = Database();

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the host and port on which the server will listen
host = '127.0.0.1'  # Loopback address (localhost)

# Bind the socket to the address and port
server_socket.bind((host, port))


while True:
    # Listen for incoming connections
    server_socket.listen(5)
    print(f"Server is listening on {host}:{port}")

    # Accept a connection from a client
    client_socket, client_address = server_socket.accept()
    print(f"Accepted connection from {client_address}")

    # Start a new thread to handle the client
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()


