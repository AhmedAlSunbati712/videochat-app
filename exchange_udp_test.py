"""
usage: python3 exchange_udp_test.py <user_type> [<peer_ip> <peer_port>]
<user_type> could be initiator or listener
"""
import sys
import time
from ChatClient import ChatClient

user_type = None
peer_ip = None
peer_port = None

our_ip = "0.0.0.0"
our_port = 3456

def parse_args():
    global user_type, peer_ip, peer_port
    if len(sys.argv) < 2:
        print("Error: usage python3 exchange_udp_test.py <user_type> [<peer_ip> <peer_port>]")
        sys.exit(1)
    
    user_type = sys.argv[1]
    
    if user_type == "initiator":
        if len(sys.argv) < 4:
            print("Error: Initiator requires peer_ip and peer_port")
            sys.exit(1)
        peer_ip = sys.argv[2]
        peer_port = int(sys.argv[3])

def main():
    global user_type, peer_ip, peer_port, our_ip, our_port


    




    parse_args()
    
    print(f"Starting {user_type} on port {our_port} ")
    
    # Initialize the client
    chat_client = ChatClient(host=our_ip, port=our_port)
    chat_client.start_receiver_thread()

    if user_type == "initiator":
        print(f"Initiating call to {peer_ip}:{peer_port}")
        time.sleep(1) 
        chat_client.send_hello(peer_ip, peer_port)
        
    elif user_type == "listener":
        print(f"Waiting for incoming call")

    try:
        while True:
            time.sleep(1)
            if chat_client.key_exchange_complete.is_set():
                chat_client.start_sender_thread()

                # Once connected, we should send the video frames here
                # just to test the encryption
                pass 
    except KeyboardInterrupt:
        print("\nKeyboard interrupt. exiting script")
    finally:
        chat_client.stop()

if __name__ == "__main__":
    main()