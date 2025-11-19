import socket
import threading
import time
import DH  
from VideoPacket import * 
import cv2
import math

class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        print(f"Client bound to {self.host}:{self.port}")

        self.peer_address = None
        self.running = threading.Event()
        self.running.set()  
        
        self.key_exchange_complete = threading.Event()
        
        # State of the key exchange process
        self.dh_params = None
        self.dh_private_key = None
        self.derived_key = None 
        
        # Two threads, one for receiving and the other for sending packets
        # (the sender only works for sending video frame packets. All the sending
        # that happens in key exchange are handled in the key exchange helper
        # functions)
        self.receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True, )

    def start_sender_thread(self):
        """
        Description: Starts the sender thread for sending video frames.
        """
        self.sender_thread.start()
        print("Sender thread started.")

    def start_receiver_thread(self):
        """
        Description: Starts the receiver and sender threads.
        """
        self.receiver_thread.start()
        print("Threads started.")

    def stop(self):
        """
        Description: Signals all threads to stop and closes the socket.
        """
        print("Stopping client...")
        self.running.clear()
        self.socket.close() 
        self.receiver_thread.join(timeout=1)
        self.sender_thread.join(timeout=1)
        print("Client stopped.")

    def _receiver_loop(self):
        """
        Description: Receiver's loop that is going to be running in the receiver thread. Recovers
                     packets from the socket and calls handle_packet on the data found there.
                     It also stores the peer address if this is the first message we are receving from them.
        """
        while self.running.is_set():
            try:
                data, addr = self.socket.recvfrom(4096)
                if not self.running.is_set():
                    break
                if not self.peer_address:
                    print(f"Got first contact from {addr}")
                    self.peer_address = addr
                self.handle_packet(data)

            except socket.error as e:
                if self.running.is_set():
                    print(f"Receiver loop socket Error: {e}")
            except Exception as e:
                if self.running.is_set():
                    print(f"Receiver loop error: {e}")

    def _sender_loop(self):
        """
        Unimplmented for now
        Description: Used for sending video frame packets
        """
        image_num = 0
        while self.running.is_set():

            cap = cv2.VideoCapture(1)

            # Warmup
            for _ in range(5):
                cap.read()

            ret, frame = cap.read()
            cap.release()

            if not ret:
                raise RuntimeError("Failed to capture image")


            h, w = frame.shape[:2]
            scale = min(400 / w, 400 / h, 1.0)
            if scale < 1.0:
                new_w = int(w * scale)
                new_h = int(h * scale)
                frame = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)

            encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), int(70)]
            success, buffer = cv2.imencode(".jpg", frame, encode_params)
            if not success:
                raise RuntimeError("Failed to encode image")

            img_bytes = buffer.tobytes()
            image_size = len(img_bytes)
            frame_count = math.ceil(image_size / 1400)
            print(f"Frame count: {frame_count}")
            for i in range(frame_count):
                frame_bytes_unencrypted = img_bytes[i*1400:(i+1)*1400]
                frame_bytes_encrypted = DH.encrypt(self.derived_key,frame_bytes_unencrypted)
                img_pkt = VideoPacket(MSG_TYPE_FRAME_DATA,image_num,i,frame_count,frame_bytes_encrypted)
                self.socket.sendto(img_pkt.to_bytes(), self.peer_address)


            image_num += 1
            time.sleep(2)




    def handle_packet(self, data):
        """
        Description: Deserializes and routes packets to the correct logic.
        
        @param data (bytes): The VideoPacket data in bytes to be handled.
        @return None
        """

        # Need to handle this thing. from_bytes doesnt take key.
        # Also, initially all communications are not encrypted
        # from_bytes already expects the data to be decrypted
        # I think this is what we need to do
        pkt = VideoPacket.from_bytes(data) 
        if pkt is None:
            print("handle_packet: Dropped corrupt/truncated packet.")
            return
        if pkt is None:
            print("handle_packet: Received a corrupt or invalid packet.")
            return

        # We only decrypt if the key exchange is done AND the message type is one that is encrypted.
        if self.key_exchange_complete.is_set():
            
            # List of message types that should be encrypted
            encrypted_types = [
                VideoPacket.MSG_TYPE_FRAME_DATA,
                VideoPacket.MSG_TYPE_HANGUP,
                VideoPacket.MSG_TYPE_NACK,
                VideoPacket.MSG_TYPE_RETRANSMIT_REQ
            ]
            
            if pkt.msg_type in encrypted_types:
                # The pkt.payload currently holds Nonce + Ciphertext
                # We overwrite it with the decrypted Raw Data
                decrypted_payload = DH.decrypt(self.derived_key, pkt.payload)
                
                if decrypted_payload is None:
                    print("handle_packet: Decryption failed (tampered/corrupt). Dropping.")
                    return

                pkt.payload = decrypted_payload

        if pkt.msg_type == MSG_TYPE_HELLO:
                print("handle_packet: Received HELLO. Sending back HELLO_ACK")
                hello_ack_pkt = VideoPacket(MSG_TYPE_HELLO_ACK)
                self.socket.sendto(hello_ack_pkt.to_bytes(), self.peer_address)
            
        elif pkt.msg_type == MSG_TYPE_HELLO_ACK:
                # If we get the hello ack, that means we are the initiator.
                # Start the initiator sequence of key exchange
                self._initiator_start_key_exchange()
        elif pkt.msg_type == MSG_TYPE_KEY_EXCHANGE_PARAMETERS:
                # The initiator will always be the one to send out the parameters
                # and the listener is always going to be the one to receive them
                self._listener_handle_parameters(pkt.payload)
        elif pkt.msg_type ==  MSG_TYPE_KEY_EXCHANGE_PUBLIC:
                # Both the listener and the initiator have to call this
                self._handle_public_key(pkt.payload)
        elif pkt.msg_type ==  MSG_TYPE_FRAME_DATA:
                # unimplemented yet
                return
        elif pkt.msg_type ==  MSG_TYPE_HANGUP:
                # unimplemented yet
                return
        elif pkt.msg_type ==  MSG_TYPE_NACK:
                # unimplemented yet
                return
        elif pkt.msg_type ==  MSG_TYPE_RETRANSMIT_REQ:

                # unimplemented yet
                return
                
    def _initiator_start_key_exchange(self):
        """
        Description: This function is called once the initiator receives a HELLO_ACK back. It generates parameters
                     for the keys, sends them to the listener, and generates public and private keys. It finally
                     sends the public key to the listener.
        @param none
        @return none
        """
        # Generate parameters
        print("Initiator_Key_Exchange: HELLO_ACK received. Starting key exchange.")
        self.dh_params = DH.generate_dh_parameters()
        
        # Serialize and send parameters
        param_bytes = DH.serialize_parameters(self.dh_params)
        param_pkt = VideoPacket(MSG_TYPE_KEY_EXCHANGE_PARAMETERS, payload=param_bytes)
        self.socket.sendto(param_pkt.to_bytes(), self.peer_address)
        print("Initiator_Key_Exchange: Sent DH parameters.")

        # Generate public key and send
        pub, priv = DH.generate_dh_keys(self.dh_params)
        self.dh_private_key = priv
        pub_bytes = DH.serialize_public_key(pub)
        pub_pkt = VideoPacket(MSG_TYPE_KEY_EXCHANGE_PUBLIC, payload=pub_bytes)
        self.socket.sendto(pub_pkt.to_bytes(), self.peer_address)
        print("Initiator_Key_Exchange: Sent public key.")

    def _listener_handle_parameters(self, param_bytes):
        """
        Description: This function is only called on the listener side during Key Exchange. Once the listener receives
                     the key parameters, they must generate their public and private keys and send them to the initiator.
        
        @param param_bytes (bytes): Bytes of the parameters object.
        @return none
        """
        # Deserialize parameters
        print("Listener_Handle_Parameters: Received DH parameters.")
        self.dh_params = DH.deserialize_parameters_bytes(param_bytes)
        
        # Generate keys and send public key
        pub, priv = DH.generate_dh_keys(self.dh_params)
        self.dh_private_key = priv
        pub_bytes = DH.serialize_public_key(pub)
        pub_pkt = VideoPacket(MSG_TYPE_KEY_EXCHANGE_PUBLIC, payload=pub_bytes)
        self.socket.sendto(pub_pkt.to_bytes(), self.peer_address)
        print("Listener_Handle_Parameters: Sent public key.")

    def _handle_public_key(self, their_pub_key_bytes):
        """
        Description: Given that we received the public key of our peer, this function calculates the shared secret
                     and the derived key used for encrypting communciation from now on.
                     
        @param their_pub_key_bytes (bytes): The peer's public key in bytes
        @return none
        """
        if self.key_exchange_complete.is_set():
            return # Already done

        print("Handle_public_key: Received peer public key.")
        if not self.dh_private_key:
            print("Handle_public_key: Error: Got a public key before generating my own.")
            return

        # Calculate shared secret and get derived key
        their_pub_key = DH.deserialize_public_key_bytes(their_pub_key_bytes)
        shared_secret = DH.calculate_shared_secret(self.dh_private_key, their_pub_key)
        self.derived_key = DH.get_derived_key(shared_secret)
        
        # Clean up all of the state params.
        self.dh_params = None
        self.dh_private_key = None
        
        self.key_exchange_complete.set()


        print(self.derived_key)
        print("KEY EXCHANGE COMPLETE")

    def send_hello(self, peer_ip, peer_port):
        """
        Description: Initiator calls this at the start to start communication with the targeted peer.
        
        @param peer_ip: IP address of the peer device.
        @param peer_port: Target port on that IP address for the peer
        
        @return none
        """
        self.peer_address = (peer_ip, peer_port)
        pkt = VideoPacket(MSG_TYPE_HELLO, payload=b"Hello!")
        self.socket.sendto(pkt.to_bytes(), self.peer_address)
        print(f"Initiator, send_hello: Sent HELLO to {self.peer_address}")