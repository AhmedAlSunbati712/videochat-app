import socket
import threading
import time
import DH  
from VideoPacket import * 
import cv2
import math
import heapq
from collections import deque, defaultdict

class ChatClient:
    def __init__(self, host, port, gui_callback=None):
        self.gui_callback = gui_callback # self.gui
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        print(f"[!] Client bound to {self.host}:{self.port}")

        self.peer_address = None
        self.running = threading.Event()
        self.key_exchange_complete = threading.Event() # To signal when key exchange is done
        self.running.set()  
        
        # ======== State of the key exchange process ==========
        self.dh_params = None
        self.dh_private_key = None
        self.derived_key = None 
        
        # ========== State to handle retransmit requests ============
        self.sent_frames_history = deque(maxlen=20)
        self.frames_history_lock = threading.Lock()
        
        # ========== State variables for listener loop ==============
        self.frames_in_progress = {} # frame_number -> List[(sequence_number, packet_data)]
        self.ready_frames = [] # min-heap elements: (frame_number, frame_data)
        self.frame_first_packet_time = [] # implmenting a fifo queue. Elements of form (frame_number, time of first packet arrival)
        self.frame_retransmit_req_record = defaultdict(int) # frame_number -> number of retransmit requests requested
        self.next_expected_frame = 0 # To figure out which frame we expect to receive next
        self.frame_timeout = 0.2 # How long should we wait before asking for a retransmit?
        self.max_retransmits = 3 # How many times should we ask for a retransmit before dropping the frame all together?
        
        # ========== Thread Management ================
        self.receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.check_retransmit_req_thread = threading.Thread(target=self._retransmit_request_loop, daemon=True)
        self.display_thread = threading.Thread(target=self.display_frames_thread, daemon=True)

    def start_sender_thread(self):
        """
        Description: Starts the sender thread for sending video frames.
        """
        self.sender_thread.start()
        self.check_retransmit_req_thread.start()
        self.display_thread.start()

        print("[!] Sender thread started.")

    def start_receiver_thread(self):
        """
        Description: Starts the receiver thread.
        """
        self.receiver_thread.start()
        print("[!] Threads started.")

    
    def stop(self):
        """
        Description: Signals all threads to stop and closes the socket.
        """
        print("[!] Stopping client...")
        self.running.clear()
        self.socket.close() 
        self.receiver_thread.join(timeout=1)
        self.sender_thread.join(timeout=1)
        self.check_retransmit_req_thread.join(timeout=1)
        self.display_thread.join(timeout=1)
        print("[!] Client stopped.")

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
                
                # If it's the first message from our peer, record their address so we can communicate with them
                if not self.peer_address:
                    print(f"[!] Got first contact from: {addr}")
                    self.peer_address = addr
                
                # Call the packer handler   
                self.handle_packet(data)
            # Error handling
            except socket.error as e:
                if self.running.is_set():
                    print(f"[!] Receiver loop socket Error: {e}")
            except Exception as e:
                if self.running.is_set():
                    print(f"[!] Receiver loop error: {e}")

    def _sender_loop(self):
        """
        Description: Used for sending video frame packets
        """
        frame_num = 0

        cap = cv2.VideoCapture(1, cv2.CAP_AVFOUNDATION)
        cap.set(cv2.CAP_PROP_FPS, 60)
        while self.running.is_set():
            ret, frame = cap.read()
            if not ret:
                raise RuntimeError("[!] Failed to capture frame")

            h, w = frame.shape[:2]
            scale = min(400 / w, 400 / h, 1.0)
            if scale < 1.0:
                new_w = int(w * scale)
                new_h = int(h * scale)
                frame = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_AREA)

            encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), int(70)]
            success, buffer = cv2.imencode(".jpg", frame, encode_params)
            if not success:
                raise RuntimeError("[!] Failed to encode frame")
            
            frame_bytes = buffer.tobytes()
            frame_size = len(frame_bytes)
            frame_pkts_count = math.ceil(frame_size / 1400)
            packets_for_this_frame = [] # Need to store to hold in history
            print(f"[*] Captured frame: {frame_num}")
            print(f"[*] Frame count: {frame_pkts_count}")
            
            # Send a frame in chunks
            for i in range(frame_pkts_count):
                # Chunk and encrypt each chunk
                chunk_bytes_unencrypted = frame_bytes[i*1400:(i+1)*1400]
                chunk_bytes_encrypted = DH.encrypt(self.derived_key,chunk_bytes_unencrypted)
                
                # Create the packet
                chunk_pkt = VideoPacket(msg_type=MSG_TYPE_FRAME_DATA, frame_num=frame_num, seq_num=i, total_packets=frame_pkts_count, payload=chunk_bytes_encrypted)
                packets_for_this_frame.append(chunk_pkt)
                
                self.socket.sendto(chunk_pkt.to_bytes(), self.peer_address) # Send immediately
            
            # Use a mutex lock to store the packets for this frame
            with self.frames_history_lock:
                self.sent_frames_history.append((frame_num, packets_for_this_frame))

            frame_num += 1
            print(f"[*] Captured and sent frame {frame_num}")
            self.gui_callback(f"selfimage,{frame_bytes}")

            time.sleep(0.2)



    def handle_packet(self, data):
        """
        Description: Deserializes, decrypts and routes packets to the correct logic.
        ========= Parameters ========
        @param data (bytes): The VideoPacket data in bytes to be handled.
        ========= Returns ========
        @return None
        """
        pkt = VideoPacket.from_bytes(data) 
        if pkt is None:
            print("[!] handle_packet: Dropped corrupt/truncated packet.")
            return

        # We only decrypt if the key exchange is done AND the message type is one that is encrypted.
        if self.key_exchange_complete.is_set():
            
            # List of message types that should be encrypted
            encrypted_types = [
                MSG_TYPE_FRAME_DATA,
                MSG_TYPE_HANGUP,
                MSG_TYPE_RETRANSMIT_REQ
            ]
            
            if pkt.msg_type in encrypted_types:
                # The pkt.payload currently holds Nonce + Ciphertext
                # We overwrite it with the decrypted Raw Data
                decrypted_payload = DH.decrypt(self.derived_key, pkt.payload)
                
                if decrypted_payload is None:
                    print("[!] handle_packet: Decryption failed (tampered/corrupt). Dropping.")
                    return

                pkt.payload = decrypted_payload

        if pkt.msg_type == MSG_TYPE_HELLO:
                self.gui_callback(f"incoming call,{self.peer_address}")
            
        elif pkt.msg_type == MSG_TYPE_HELLO_ACK:
                # If we get the hello ack, that means we are the initiator.
                # Start the initiator sequence of key exchange
                self.gui_callback("hello_ack_received")
                self._initiator_start_key_exchange()
                
        elif pkt.msg_type == MSG_TYPE_KEY_EXCHANGE_PARAMETERS:
                # The initiator will always be the one to send out the parameters
                # and the listener is always going to be the one to receive them
                self._listener_handle_parameters(pkt.payload)
                
        elif pkt.msg_type ==  MSG_TYPE_KEY_EXCHANGE_PUBLIC:
                # Both the listener and the initiator have to call this
                self._handle_public_key(pkt.payload)
                
        elif pkt.msg_type ==  MSG_TYPE_FRAME_DATA:
                self._frame_data_packet_handler(pkt)            
        elif pkt.msg_type ==  MSG_TYPE_HANGUP:
                self.hangup()
                self.gui_callback("hangup")
        elif pkt.msg_type ==  MSG_TYPE_NACK:
                self.gui_callback("nack")
        elif pkt.msg_type ==  MSG_TYPE_RETRANSMIT_REQ:
                print("RECEIVED RETRANSMIT REQ")
                self.handle_retransmit(pkt)
            
    def handle_retransmit(self, pkt: VideoPacket):
        """
        Description: Handles retransmit requests. It fetches the frame number to be sent from
                     pkt.frame_num. It then locks the frame_history lock so that it could extract
                     the frame data from self.sent_frames_history without competing with the video
                     capture thread in race conditions (the capture thread modifies the history with
                     every new frame it takes).
        ============== Parameters ==============
        @param pkt: The VideoPacket object associated with the retransmit request that we received.
        ============== Returns ============
        @return void, but sends back to peer the requested frame back if not found.
        """
        found_frame = False
        packets_to_resend = []
        frame_num = pkt.frame_num
        
        # Search through history, making sure to acquire the lock first:
        with self.frames_history_lock:
            if not self.sent_frames_history:
                print(f"[!] Request for {frame_num} denied: History is empty.")
                return
            
            # Since the frame numbers in the history are contigious, we can use this trick for O(1) lookup
            left_endpoint_frame_num = self.sent_frames_history[0][0] 
            idx = frame_num - left_endpoint_frame_num
            if 0 <= idx < len(self.sent_frames_history):
                # Double checking because I'm paranoid
                if self.sent_frames_history[idx][0] == frame_num:
                    found_frame = True
                    packets_to_resend = self.sent_frames_history[idx][1]
        
        if found_frame:
            print(f"[+] Resending frame {frame_num} ({len(packets_to_resend)} packets)")
            for frame_pkt in packets_to_resend:
                self.socket.sendto(frame_pkt.to_bytes(), self.peer_address)
        else:
            print(f"[!] Couldn't find frame {frame_num} in history! It's too old!")
        
    def _frame_data_packet_handler(self, pkt: VideoPacket):
        """
        Description: Handler for packet of type MSG_TYPE_FRAME_DATA. If the frame in this packet is an old
                     frame, drop it. Otherwise, add its packet to the other packets associated with the frame
                     in the dictionary self.frames_in_progress. It checks if we received all the packets for the
                     frame after each packet. If so, it assembles the frame in order and pushes it on the min-heap
                     to be displayed.
        ================ Parameters ================
        @param pkt: The frame packet to be processed.
        ================ Returns ==================
        @return void
        """
        def assemble_frame(seq_data_pairs):
            """
            Description: Helper functionality for assembling frame's data after all packets arrive.
            =========== Parameteers =======
            @param seq_data_pairs (List): An array of (seq_num, pkt.payload) associated with a frame.
                                          Array is sorted by key=seq_num.
            ========== Returns ========
            @return frame_data (bytes): The frame data assembled in order.
            """
            sorted_packets = sorted(seq_data_pairs, key=lambda x: x[0])
            frame_data = b""
            for (seq_number, packet_data) in sorted_packets:
                frame_data += packet_data
            return frame_data
        
        # Retrieve frame_num and check if it's an old frame
        frame_number = pkt.frame_num
        if (frame_number < self.next_expected_frame):
            return # drop
        
        # pkt header
        seq_number = pkt.seq_num
        packet_video_data = pkt.payload
        total_packets = pkt.total_packets
        
        # If this is the first packet we receive from this frame
        if frame_number not in self.frames_in_progress.keys():
            # Initialize entries for this frame
            self.frames_in_progress[frame_number] = []
            self.frame_first_packet_time.append((frame_number, time.time()))
            self.frame_retransmit_req_record[frame_number] = 0
        
        # Append this packet to the list of packets associated with this frame
        self.frames_in_progress[frame_number].append((seq_number, packet_video_data))
        
        # If we received all of the packets for this frame
        if len(self.frames_in_progress[frame_number])  == total_packets:
            print(f"[!] Received a full image! Frame number is {frame_number}")
            frame_data = assemble_frame(self.frames_in_progress[frame_number]) # Assemble the frame
            
            # Clean up
            self._remove_frame_time_record(frame_number) # remove from frame_first_packet_time
            del self.frames_in_progress[frame_number] # remove from frames_in_progress dict
            del self.frame_retransmit_req_record[frame_number] # remove from retransmit_req_record
            
            # Frame is ready push it onto the heap to be consumed by the display thread
            heapq.heappush(self.ready_frames, (frame_number, frame_data))
        
    def _retransmit_request_loop(self):
        """
        Description: Checks if any frame has reached timeout. If so, it cleans its records and ask for
                     a retransmit if it hasn't already reached the maximum number of retransmits already.
                     If it did reach the maximum number of retransmits, the frame is dropped alltogether and
                     the counter for the next_expected frame is incremented so as to signal to not wait for this
                     specific frame anymore.
        @param None
        @return None
        """
        def send_retransmit_request(frame_num):
            """
            Decsription: Helper functionality to send a retransmit request packet for a given frame
            ============ Parameters =========
            @param frame_num: The frame number to be requested.
            ============ Returns =========
            @return None. Sends a retransmit request packet over the socket to our peer
            """
            print("SENDING RETRANSMIT ReQUEST fr")
            pkt = VideoPacket(msg_type=MSG_TYPE_RETRANSMIT_REQ, frame_num=frame_num)
            self.socket.sendto(pkt.to_bytes(), self.peer_address)
        while self.running.is_set():
            # Check if we reached timeout on any frame   
            i = 0
            while i < len(self.frame_first_packet_time):
            # for i in range(len(self.frame_first_packet_time)):
                frame_time_record = self.frame_first_packet_time[i]
                frame_num = frame_time_record[0]
                time_elapsed = time.time() - frame_time_record[1]
                
                # If timed out
                if time_elapsed >= self.frame_timeout:
                    # Clean up since we are gonna ask for a retransmit for this frame
                    self._remove_frame_time_record(frame_num) # Pop the time record so we prepare for the next first packet associated with the frame
                    del self.frames_in_progress[frame_num] # remove from frames_in_progress dict (since we are receiving the packets all over again)
                    self.frame_retransmit_req_record[frame_num] += 1 # increment retransmit request record

                    # Only retransmit if we haven't reached the maximum number of retransmits allowed
                    if self.frame_retransmit_req_record[frame_num] <= self.max_retransmits:
                        print(f"[*] Sending a retransmit request for frame number {frame_num}")
                        send_retransmit_request(frame_num)
                    else:
                        # If we reached the maximum number of requests, just drop the frame and move on to waiting on the next one
                        print(f"[*] Timed out for frame {frame_num}.")
                        self.next_expected_frame += 1
                        del self.frames_in_progress[frame_num] # remove from frames_in_progress dict
                        del self.frame_retransmit_req_record[frame_num]  # remove from retransmit_req_record
                        self._remove_frame_time_record(frame_num)
                        self.next_expected_frame += 1
                    i += 1
                time.sleep(0.1)
                
        
    def display_frames_thread(self):
        """
        Description: Display loop. It checks if there are any frames ready on the heap to be displayed.
                     if the smallest frame number on the heap is not equal to the next_expected frame,
                     then we have to wait until we have the next frame ready to be displayed.
        @param None
        @return None. Displays frame
        """
        while self.running.is_set():
            if len(self.ready_frames) != 0 and self.ready_frames[0][0] == self.next_expected_frame:
                frame_num, frame_data = heapq.heappop(self.ready_frames)
                self.gui_callback("peerimage",frame_data)
                self.next_expected_frame += 1
            
                
        
    def accept_call(self):
        """
        Description: Called by the GUI when the user accepts an incoming call.
        Currently does nothing as the HELLO_ACK is already sent when the HELLO is received.
        """
        print("[!] handle_packet: Received HELLO. Sending back HELLO_ACK")
        hello_ack_pkt = VideoPacket(MSG_TYPE_HELLO_ACK)
        self.socket.sendto(hello_ack_pkt.to_bytes(), self.peer_address)

    def decline_call(self):
        """
        Description: Called by the GUI when the user declines an incoming call.
        Currently does nothing.
        """
        nack_pkt = VideoPacket(MSG_TYPE_NACK)
        self.socket.sendto(nack_pkt.to_bytes(), self.peer_address)

    def hang_up(self,sendpack=False):
        """
        Description: Stops sending and receiving. Called by the GUI when the user hangs up the call, OR called internally when we receive a HANGUP packet from the peer.
        @param sendpack (bool): Whether to send a HANGUP packet to the peer
        """
        self.stop()
        
        if sendpack:
            hangup_pkt = VideoPacket(MSG_TYPE_HANGUP)
            self.socket.sendto(hangup_pkt.to_bytes(), self.peer_address)


    def _initiator_start_key_exchange(self):
        """
        Description: This function is called once the initiator receives a HELLO_ACK back. It generates parameters
                     for the keys, sends them to the listener, and generates public and private keys. It finally
                     sends the public key to the listener.
        @param none
        @return none
        """
        # Generate parameters
        print("[!] Initiator_Key_Exchange: HELLO_ACK received. Starting key exchange.")
        self.dh_params = DH.generate_dh_parameters()
        
        # Serialize and send parameters
        param_bytes = DH.serialize_parameters(self.dh_params)
        param_pkt = VideoPacket(MSG_TYPE_KEY_EXCHANGE_PARAMETERS, payload=param_bytes)
        self.socket.sendto(param_pkt.to_bytes(), self.peer_address)
        print("[*] Initiator_Key_Exchange: Sent DH parameters.")

        # Generate public key and send
        pub, priv = DH.generate_dh_keys(self.dh_params)
        self.dh_private_key = priv
        pub_bytes = DH.serialize_public_key(pub)
        pub_pkt = VideoPacket(MSG_TYPE_KEY_EXCHANGE_PUBLIC, payload=pub_bytes)
        self.socket.sendto(pub_pkt.to_bytes(), self.peer_address)
        print("[*] Initiator_Key_Exchange: Sent public key.")

    def _listener_handle_parameters(self, param_bytes):
        """
        Description: This function is only called on the listener side during Key Exchange. Once the listener receives
                     the key parameters, they must generate their public and private keys and send them to the initiator.
        
        @param param_bytes (bytes): Bytes of the parameters object.
        @return none
        """
        # Deserialize parameters
        print("[!] Listener_Handle_Parameters: Received DH parameters.")
        self.dh_params = DH.deserialize_parameters_bytes(param_bytes)
        
        # Generate keys and send public key
        pub, priv = DH.generate_dh_keys(self.dh_params)
        self.dh_private_key = priv
        pub_bytes = DH.serialize_public_key(pub)
        pub_pkt = VideoPacket(MSG_TYPE_KEY_EXCHANGE_PUBLIC, payload=pub_bytes)
        self.socket.sendto(pub_pkt.to_bytes(), self.peer_address)
        print("[*] Listener_Handle_Parameters: Sent public key.")

    def _handle_public_key(self, their_pub_key_bytes):
        """
        Description: Given that we received the public key of our peer, this function calculates the shared secret
                     and the derived key used for encrypting communciation from now on.
                     
        @param their_pub_key_bytes (bytes): The peer's public key in bytes
        @return none
        """
        if self.key_exchange_complete.is_set():
            return # Already done

        print("[!] Handle_public_key: Received peer public key.")
        if not self.dh_private_key:
            print("[!] Handle_public_key: Error: Got a public key before generating my own.")
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
        print("[+] KEY EXCHANGE COMPLETE")
        self.start_sender_thread()


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
        print(f"[*] Initiator, send_hello: Sent HELLO to {self.peer_address}")
        
        
    def _remove_frame_time_record(self, frame_num):
        """
        search array and remove element with element[0] == frame_number
        found it useful to have this helper function since this routine is used
        in a couple of places
        """
        for i in range(len(self.frame_first_packet_time)):
            frame_time_record = self.frame_first_packet_time[i]
            if frame_time_record[0] == frame_num:
                self.frame_first_packet_time.pop(i)
                break