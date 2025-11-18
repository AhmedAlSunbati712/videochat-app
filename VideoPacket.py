"""
VideoPacket.py     Ahmed Al Sunbati     Nov 13th, 2025
Description: Custom application-layer packet to handle the videochat communication logic

Citations: ChatGPT for writing the documentation in each API service in a nice format
"""

import struct, json, zlib

HEADER_FORMAT = "!BIHHHI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

MSG_TYPE_HELLO = 1
MSG_TYPE_HELLO_ACK = 2
MSG_TYPE_NACK = 3
MSG_TYPE_KEY_EXCHANGE_PARAMETERS = 4
MSG_TYPE_KEY_EXCHANGE_PUBLIC = 5
MSG_TYPE_FRAME_DATA = 6
MSG_TYPE_RETRANSMIT_REQ = 7
MSG_TYPE_HANGUP = 8


class VideoPacket:
    def __init__(self, msg_type, frame_num=0, seq_num=0, total_packets=0, payload=b"", checksum=0):
        """
        Description: Represents a custom application-layer packet used for transmitting control
                     messages and video frame fragments over UDP. The packet contains a fixed-size
                     header and a variable-length payload, along with a CRC32 checksum for corruption
                     detection.

        @param msg_type: Type of message (HELLO, FRAME_DATA, ...etc)
        @param frame_num: Frame index this packet belongs to (0 if not applicable)
        @param seq_num: Sequence number of this packet within a frame
        @param total_packets: Total number of packets that compose the frame
        @param payload: Raw message or frame data
        @param checksum: CRC32 checksum for verifying packet integrity

        @return None

        """
        self.msg_type = msg_type
        self.frame_num = frame_num
        self.seq_num = seq_num
        self.total_packets = total_packets
        self.payload  = payload
        self.checksum = checksum
        
    def to_bytes(self):
        """
        Description: Serializes the VideoPacket into a byte string suitable for sending over a UDP socket.
                     Builds a header without checksum, computes the CRC32 checksum over header+payload,
                     then packs the final header including checksum.

        @param self: VideoPacket instance

        @return (bytes) Serialized packet containing header + payload
        """
        payload_len = len(self.payload)
        
        header_wo_checksum = struct.pack(
            "!BIHHH",
            self.msg_type,
            self.frame_num,
            self.seq_num,
            self.total_packets,
            payload_len
        )
        
        crc = zlib.crc32(header_wo_checksum + self.payload) & 0xFFFFFFFF
        self.checksum = crc
        
        header = struct.pack(
            HEADER_FORMAT,
            self.msg_type,
            self.frame_num,
            self.seq_num,
            self.total_packets,
            payload_len,
            self.checksum
        )
        
        return header + self.payload
    
    def serialize(self):
        """
        Description: Alias for to_bytes() provided for semantic clarity. Produces the raw byte
                     representation of the packet.

        @param self: VideoPacket instance

        @return (bytes) Serialized packet data
        """
        return self.to_bytes
    
    @staticmethod
    def from_bytes(data):
        """
        Description: Parses a VideoPacket from its byte representation. Unpacks the header according
                     to HEADER_FORMAT, extracts the payload, and returns a reconstructed VideoPacket
                     object.

        @param data: (bytes) Raw received packet data

        @return (VideoPacket) Parsed packet instance
        """
        header = data[:HEADER_SIZE]
        msg_type, frame_num, seq_num, total_packets, payload_len, checksum = struct.unpack(
            HEADER_FORMAT, header
        )
        
        payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
        
        return VideoPacket(
            msg_type=msg_type,
            frame_num=frame_num,
            seq_num=seq_num,
            total_packets=total_packets,
            payload=payload,
            checksum=checksum   
        )
    
    @staticmethod
    def deserialize(data):
        """
        Description: Convenience wrapper for from_bytes() to mirror the serialize() API.

        @param data: (bytes) Raw packet data

        @return (VideoPacket) Parsed packet
        """
        return VideoPacket.from_bytes(data)
    
    def is_corrupted(self):
        """
        Description: Checks whether the packet's checksum matches its contents. Recomputes CRC32 over
                     (header-without-checksum + payload) and compares it to the checksum field.

        @param self: VideoPacket instance

        @return (bool) True if checksum does not match (packet is corrupted), else False
        """
        header_wo_checksum = struct.pack(
            "!BIHHH",
            self.msg_type,
            self.frame_num,
            self.seq_num,
            self.total_packets,
            len(self.payload)
        )
        crc = zlib.crc32(header_wo_checksum + self.payload) & 0xFFFFFFFF
        return crc != self.checksum


