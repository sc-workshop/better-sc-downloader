import os
from socket import socket, create_connection
import json
from struct import unpack
from .writer import Writer
from .reader import Reader
import zlib

from enum import Enum


class HelloServerResponse(Enum):
    Success = 7
    NeedUpdate = 8


class Client:
    def __init__(self, assets_path: str) -> None:
        self.assets_path = assets_path
        self.fingerprint_filepath = os.path.join(assets_path, "fingerprint.json")

        self.socket: socket = None
        self.major = 0
        self.build = 0
        self.revision = 0
        self.dump = False
        self.assets_url = ""
        self.assets_url_2 = ""
        self.content_url = ""

        self.fingerprint: dict = {}
        if os.path.exists(self.fingerprint_filepath):
            data_file = open(self.fingerprint_filepath, "rb")
            self.fingerprint = json.load(data_file)
            data_file.close()
            
            self.major, self.build, self.revision = self.content_version

    @property
    def content_version(self) -> list[int, int, int]:
        if self.fingerprint:
            version = str(self.fingerprint["version"]).split(".")
            return [int(num) for num in version]

        return [0, 0, 0]
    
    @property
    def content_hash(self) -> str:
        if self.fingerprint:
            return self.fingerprint.get("sha") or ""

        return ""

    def handle_packet(self) -> bytes:
        header = self.socket.recv(7)
        packet_length = int.from_bytes(header[2:5], "big")

        received_data = b""
        while packet_length > 0:
            chunk = self.socket.recv(packet_length)
            if not chunk:
                raise EOFError
            received_data += chunk
            packet_length -= len(chunk)

        return received_data

    def send_packet(self, id: int, data: bytes) -> bytes:
        packet = Writer()
        packet.writeUShort(id)
        packet.buffer += len(data).to_bytes(3, "big")
        packet.writeUShort(0)
        packet.buffer += data
        self.socket.send(packet.buffer)

        return self.handle_packet()
    
    def disconnect(self) -> None:
        self.socket.close()

    def connect(self, address: str) -> HelloServerResponse:
        self.socket = create_connection((address, 9339))

        # HelloMessage
        stream = Writer()

        stream.writeUInt32(0)  # Protocol Version
        stream.writeUInt32(11)  # Key Version
        stream.writeUInt32(self.major)  # major
        stream.writeUInt32(self.revision)  # revision
        stream.writeUInt32(self.build)  # build (minor)
        stream.writeString("")  # ContentHash
        stream.writeUInt32(2)  # DeviceType
        stream.writeUInt32(2)  # AppStore

        server_data_buffer = self.send_packet(10100, stream.buffer)
        server_data_stream = Reader(server_data_buffer)

        if self.dump:
            os.makedirs("dumps/", exist_ok=True)
            open(f"dumps/{address}.{self.major}.{self.build}.10100.bin", "wb").write(
                server_data_buffer
            )

        status_code = server_data_stream.readUInt32()

        if status_code == 7:
            server_data_stream.readUInt32()
            server_data_stream.readUInt32()

            self.content_url = server_data_stream.readString()

            server_data_stream.readUInt32()

            serialized_fingerprint = server_data_stream.readString()

            # If decompressed data length is 0 then decompress data with zlib
            if len(serialized_fingerprint) == 0:
                # Skip zeros bytes
                server_data_stream.seek(5, 1)

                # decompressInMySQLFormat
                compressed_data_length = server_data_stream.readUInt32()
                # For some reason decompressed size is in Little Endian
                decompressed_data_length = unpack("<I", server_data_stream.read(4))[0]

                compressed_data = server_data_stream.read(compressed_data_length)
                decompressed_data = zlib.decompress(compressed_data)

                if len(decompressed_data) != decompressed_data_length:
                    print("Data may be corrupted but we try to deserialize it anyway")

                serialized_fingerprint = decompressed_data.decode("utf8")

            #with open(self.fingerprint_filepath, "w", encoding="utf8") as file:
            #    file.write(serialized_fingerprint)

            self.fingerprint = json.loads(serialized_fingerprint)

            self.assets_url = server_data_stream.readString()
            self.assets_url_2 = server_data_stream.readString()

        return HelloServerResponse(status_code)
