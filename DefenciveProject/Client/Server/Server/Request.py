HEADER_SIZE = 23
PACKET_SIZE = 1024
VERSION = 3
import struct
class Request:
    def __init__(self):
        self.uuid = 0
        self.version = VERSION
        self.code = 0
        self.payloadSize = 0
        self.payload = b''

    def unpack(self, data):
        try:
          
            #unPacking header
            header_data = data[:HEADER_SIZE]
            self.uuid, self.version, self.code, self.payloadSize = struct.unpack(f'<16sBHI', header_data)

            # Unpacking payload
            payload_data = data[HEADER_SIZE:HEADER_SIZE + self.payloadSize]
            self.payload = payload_data
        except Exception as e:
            print(e)