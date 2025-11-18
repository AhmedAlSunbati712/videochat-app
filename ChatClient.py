import socket
import threading
import time
import DH  
from VideoPacket import * 

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
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)

    def start(self):
        """
        Description: Starts the receiver and sender threads.
        """
        self.receiver_thread.start()
        self.sender_thread.start()
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
        return

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
        if self.key_exchange_complete.is_set():
            data = DH.decrypt(self.derived_key, data)
        pkt = VideoPacket.from_bytes(data) 
        
        if pkt is None:
            print("handle_packet: Received a corrupt or invalid packet.")
            return

        match pkt.msg_type:
            case VideoPacket.MSG_TYPE_HELLO:
                print("handle_packet: Received HELLO. Sending back HELLO_ACK")
                hello_ack_pkt = VideoPacket(MSG_TYPE_HELLO_ACK)
                self.socket.sendto(hello_ack_pkt.to_bytes(), self.self.peer_address)
            
            case VideoPacket.MSG_TYPE_HELLO_ACK:
                # If we get the hello ack, that means we are the initiator.
                # Start the initiator sequence of key exchange
                self._initiator_start_key_exchange()
                
            case VideoPacket.MSG_TYPE_KEY_EXCHANGE_PARAMETERS:
                # The initiator will always be the one to send out the parameters
                # and the listener is always going to be the one to receive them
                self._listener_handle_parameters(pkt.payload)
                
            case VideoPacket.MSG_TYPE_KEY_EXCHANGE_PUBLIC:
                # Both the listener and the initiator have to call this
                self._handle_public_key(pkt.payload)
            
            case VideoPacket.MSG_TYPE_FRAME_DATA:
                # unimplemented yet
                return
            
            case VideoPacket.MSG_TYPE_HANGUP:
                # unimplemented yet
                return
            
            case VideoPacket.MSG_TYPE_NACK:
                # unimplemented yet
                return
            
            case VideoPacket.MSG_TYPE_RETRANSMIT_REQ:
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