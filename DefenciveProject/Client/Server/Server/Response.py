VERSION = 3
import struct
class Response:
    def __init__(self):
        self.version = VERSION
        self.code = 0
        self.payloadSize = 0
        self.payload = b''

    def pack(self):
       
        data = struct.pack('<BHI', self.version,self.code, self.payloadSize)
        data += self.payload

        return data

