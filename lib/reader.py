from io import BufferedReader, BytesIO
from struct import unpack


class Reader(BufferedReader):
    def __init__(self, initial_bytes: bytes):
        super(Reader, self).__init__(BytesIO(initial_bytes))

    def readUInt64(self) -> int:
        return unpack('>Q', self.read(8))[0]

    def readInt64(self) -> int:
        return unpack('>q', self.read(8))[0]

    def readUInt32(self) -> int:
        return unpack('>I', self.read(4))[0]

    def readInt32(self) -> int:
        return unpack('>i', self.read(4))[0]

    def readUInt16(self) -> int:
        return unpack('>H', self.read(2))[0]

    def readInt16(self) -> int:
        return unpack('>h', self.read(2))[0]

    def readUInt8(self) -> int:
        return unpack('>B', self.read(1))[0]

    def readInt8(self) -> int:
        return unpack('>b', self.read(1))[0]

    readULong = readUInt64
    readLong = readInt64

    readUShort = readUInt16
    readShort = readInt16

    readUByte = readUInt8
    readByte = readInt8

    def readChar(self, length: int = 1) -> str:
        return self.read(length).decode('utf-8')

    def readString(self) -> str:
        length = self.readUInt32()
        if length == 2**32 - 1 or length == 0:
            return ''
        else:
            return self.readChar(length)
