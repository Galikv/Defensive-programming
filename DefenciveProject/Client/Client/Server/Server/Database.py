import sqlite3
from datetime import datetime

class Database:
   
    def __init__(self):
        
        conn = self.connect_db()
        
        conn.execute("""CREATE TABLE IF NOT EXISTS clients (
                       ID CHAR(16),
                       userName CHAR(255),  
                       publicKey CHAR(160),
                       lastSeen DATE,
                       aes CHAR(128)
                       );""")
        conn.execute("""CREATE TABLE IF NOT EXISTS files (
                           ID CHAR(16),
                           fileName CHAR(255),
                           pathName CHAR(255),
                           verified BOOLEAN
                           );""")
        conn.commit()
        conn.close()

    def connect_db(self):
        conn = sqlite3.connect('defensive.db')
        conn.text_factory = bytes
        return conn
        
    #Register
    def Register(self, id , name):

        conn = self.connect_db()
        cursor = conn.cursor()

        #add user to dataBase
        cursor.execute("""INSERT INTO clients (ID, userName) VALUES (?, ?)""", (id, name))
        conn.commit()
        conn.close()
        
    #find user by ID
    def ifExsistsByID(self, id):

        conn = self.connect_db()
        cursor = conn.cursor()

        #Get user from dataBase by ID
        cursor.execute("""SELECT * FROM clients WHERE ID = ?""", (id,))
        isExsists = cursor.fetchall()

        conn.commit()
        self.close()

        if isExsists:
            return True
        return False

    #find user by name
    def ifExsistsByName(self, name):

        conn = self.connect_db()
        cursor = conn.cursor()

        #Get user from dataBase by name
        cursor.execute("""SELECT * FROM clients WHERE userName = ?""", (name,))
        isExsists = cursor.fetchall()

        conn.commit()
        conn.close()

        if isExsists:
            return True
        return False

    #get ID by user name
    def getIdByName(self,name):

        conn = self.connect_db()
        cursor = conn.cursor()

        #Get user from database by name
        cursor.execute("""SELECT ID FROM clients WHERE userName = ?""", (name,))
        id = cursor.fetchall()

        conn.commit()
        conn.close()
        if id:
            return id[0][0]
        else:
            return None

    #add public key by user ID
    def addPublicKey(self, key ,id):

        conn = self.connect_db()
        cursor = conn.cursor()

        #add key to user by ID
        cursor.execute("""UPDATE clients SET publicKey = ? WHERE ID = ?""", (key, id))

        conn.commit()
        conn.close()

    #get public key by user ID
    def getPublicKey(self,id):

        conn = self.connect_db()
        cursor = conn.cursor()

        #get key to user by ID
        cursor.execute("""SELECT publicKey FROM clients WHERE ID = ?""", (id,))
        key = cursor.fetchall()

        conn.commit()
        conn.close()
        if key:
            return key[0][0]
        else:
            return None

    #add AES key by user ID
    def addAESKey(self, key, id):

        conn = self.connect_db()
        cursor = conn.cursor()

        #add key to user by ID
        cursor.execute("""UPDATE clients SET aes = ? WHERE ID = ?""", (key, id))

        conn.commit()
        conn.close()

    #get AES key by user ID
    def getAESKey(self, id):

        conn = self.connect_db()
        cursor = conn.cursor()

        #get key by user ID
        cursor.execute("""SELECT aes FROM clients WHERE ID = ?""", (id,))
        aes_key = cursor.fetchall()

        conn.commit()
        conn.close()
        return aes_key[0][0]

     #update last seen
    def setLastSeen(self, id):

        conn = self.connect_db()
        cursor = conn.cursor()

        # Get the current timestamp
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Update in dataBase
        cursor.execute("""UPDATE clients SET lastSeen = ? WHERE ID = ?""", (current_time, id))

        conn.commit()
        conn.close()

        #add file name
    def addFileName(self, id , fileName):

        conn = self.connect_db()
        cursor = conn.cursor()

        #add file to dataBase
        cursor.execute("""INSERT INTO files (ID, fileName) VALUES (?, ?)""", (id, fileName))
        conn.commit()
        conn.close()

    def addCrc(self, id , crc):

        conn = self.connect_db()
        cursor = conn.cursor()

         #add to dataBase
        cursor.execute("""UPDATE files SET verified = ? WHERE ID = ?""", (crc, id))

        conn.commit()
        conn.close()

    def addPath(self, id , path):

        conn = self.connect_db()
        cursor = conn.cursor()

        #add to dataBase
        cursor.execute("""UPDATE files SET pathName = ? WHERE ID = ?""", (path, id))

        conn.commit()
        conn.close()

      


