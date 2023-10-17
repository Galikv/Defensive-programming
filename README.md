# Defensive-programming
Implement server and client software that allows customers to transfer encrypted files from their computer to storage on the server. The server is written in Python, while the client is written in C++.
-The client needs to register or log in ,then generates and sends RSA public key.
-the server in response generates AES key and encryptes it with the public key.
-the client after decrypting the AES key , encrypts a local file with AES key and then sends it to the server.
-the server decrypts the file and saves it to database.
  - the server database contains:2 tables
  - the first contains: unique id , name , public key , last seen , AES key
  - the second one contains: unique id , file name , file path , verified
