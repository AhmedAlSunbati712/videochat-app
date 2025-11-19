from scapy.all import *

def print_packet(packet):
    """
    This function is called for each sniffed packet and prints its summary.
    """
    print(packet.summary()) # Or packet.show() for more detail

# Sniff packets indefinitely and print a summary of each
# You can add a 'count' argument to limit the number of packets, e.g., count=10
sniff(prn=print_packet) 
