import socket #provides access to BDS socket interface allowing us to create a raw socket
import struct #provides tool for working with c style ds and use to unapack ehternet pattern

sus_patterns = ['danger.com','unautherized_acccess']

# packet sniffing function 
# creating a socket which allows prigram to capture all network packets at the data link layer 

def sniff_packet():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        raw_data, addr = sock.recvfrom(65535) #capture packets, buffer size is 65535 to accomodate large packets 
        eth_header = raw_data[:14]
        eth_data = struct.unpack('!6s6sH', eth_header) #former specifier that defines how to interpret the byte data from the ethernet header
        # !: data should be interpreted in network byte order (big-endian)
        #6s: desitnation MAC address
        #6s: similar to previous one, indictes src MAC
        #H: specifies that next part of the data is unsigned short (2bytes) -> EtherType (protocol type)

        # interpreting the first 14 bytes of the internet frame  6 6 2, this unpacked data can then be used for the processing and analysis in our intrusion detection system 

    # NOW, checking sus patterns
        payload = raw_data[14:] # rest of the pack starting from 15 byte is considered payload, checking if any of sus pattern is in the payload
        print(f"Packet received from: {addr}")
        for pattern in sus_patterns:
            if pattern.encode() in payload:
                print(f'suspicious activity detected: {pattern} in {addr}')

if __name__ == '__main__':
    print('Starting packet sniffer, intrusion detection!')
    sniff_packet()


