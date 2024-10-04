#! /usr/bin/python3
# Python 3.10
# Autor: Jakub Martinak
# Login: xmartinakj

import socket
import struct
import binascii
import os
import math
import random
import re

# CONFIG    ====================================================
IP_CLIENT = "localhost"
PORT_CLIENT = 8000
IP_SERVER = "localhost"
PORT_SERVER = 8000
MAX_PACKET_SIZE = 1469
HEADER_SIZE = 9
MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
PACKET_TYPES = {
    "SYN": 0x01,
    "DATA": 0x02,
    "ACK": 0x03,
    "FIN": 0x04,
    "FINACK": 0x05,
    "CHANGE": 0x06,
    "ERROR": 0x07,
}

"""
    Header:
        1b typ
        3b cislo sekvencie
        3B pocet fragmentov
        2B crc
        Payload size = 1459 bytes
        full packet size = 1469 bytes
"""


# ==============================================================

# FUNCTIONS ====================================================

def get_ethernet_ip():
    try:
        # Create a dummy socket to make a connection
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Connect to a public DNS server (Google's 8.8.8.8) on port 80
        s.connect(("8.8.8.8", 80))

        # Get the local IP address to which the socket is connected
        ip = s.getsockname()[0]
        print(ip)

        s.close()
        return ip
    except Exception:
        return "Unable to determine Ethernet IP"


def corrupt_packet(packet, corruption_rate=0.01):
    """
    Simulates packet corruption by randomly altering some of the bytes.

    Args:
    - packet (bytes): The original packet data.
    - corruption_rate (float): The probability of each byte being altered.

    Returns:
    - bytes: The corrupted packet.
    """
    corrupted_packet = bytearray(packet)
    for i in range(len(corrupted_packet)):
        if random.random() < corruption_rate:
            corrupted_packet[i] = corrupted_packet[i] ^ random.getrandbits(8)
    return bytes(corrupted_packet)


def calculate_total_chunks(file_path, chunk_size):
    # Get the size of the file
    file_size = os.path.getsize(file_path)

    # Calculate the number of chunks
    total_chunks = math.ceil(file_size / chunk_size)
    return total_chunks


def file_to_chunks(file_p, chunk_size):
    """
    Generator that reads a file in chunks of chunk_size bytes.
    :param file_p:
    :param chunk_size:
    :return: chunk of data
    """

    with open(file_p, 'rb') as file:
        chunk_count = 0
        while True:
            chunky = file.read(chunk_size)
            if not chunky:
                break
            chunk_count += 1
            yield chunky


def calculate_crc16(data, initial_value=0):
    """
    Calculate the CRC16 checksum for the given data.

    Args:
    - data (bytes): The data for which to compute the checksum.
    - initial_value (int): The initial value of the checksum. Default is 0.

    Returns:
    - int: The computed CRC16 checksum.
    """
    return binascii.crc_hqx(data, initial_value)


def int_to_3bytes(num):
    """
    Convert an integer to a 3-byte long byte object.

    Args:
    - num (int): The integer to convert. Must be in the range 0 to 16,777,215.

    Returns:
    - bytes: The 3-byte long byte object.
    """
    if not 0 <= num <= 0xFFFFFF:
        raise ValueError("Number out of range for 3 bytes")
    return num.to_bytes(3, byteorder='big')


def send_packet(sock, packet, address, timeout=5):
    try:
        sock.settimeout(timeout)
        sock.sendto(packet, address)

        # Wait for ACK
        response, IP_SERVER = sock.recvfrom(1024)  # Buffer size for ACK
        if int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("ACK"):
            return response
        elif int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("ERROR"):
            return response
        elif int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("CHANGE"):
            return response
        elif int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("FINACK"):
            return response
    except socket.timeout:
        count = 0
        while count < 3:
            print("Timeout, resending packet...")
            sock.sendto(packet, address)
            try:
                ack, _ = sock.recvfrom(1024)  # Buffer size for ACK
                return ack
            except socket.timeout:
                count += 1
        print("Server not responding, closing connection...")
        return None


def split_into_chunks(message, chunk_size):
    return [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]


def calculate_chunk_count(message_length, chunk_size):
    return math.ceil(message_length / chunk_size)


def extract_filename(path):
    pattern = r'[^/\\]+$'
    match = re.search(pattern, path)
    if match:
        return match.group()
    return None

# ==============================================================


class CustomHeader:
    def __init__(self, command, sequence_number, fragment_count, crc):
        self.command = command
        self.sequence_number = sequence_number
        self.fragment_count = fragment_count
        self.crc = crc
        # self.flags = flags

    def serialize(self):
        # The sequence_number and file_path must be converted to bytes if they are not already
        # CRC is a numerical value, computed over the data
        # Flags is a numerical value, fitting within 1 byte
        return struct.pack('!B3s3sH', self.command, self.sequence_number, self.fragment_count, self.crc)

    @staticmethod
    def deserialize(data):
        unpacked_data = struct.unpack('!B3s3sH', data)
        return CustomHeader(*unpacked_data)


client_socket = None
server_socket = None
count_of_starts = 0
count_of_switches = 0
chose_input = None
switch_initiated = False

while True:
    if count_of_starts == 0 and not switch_initiated:
        print("==========================================================")
        print("Please choose if you want to be a client or server")
        print("After sending message/file, you will be asked to choose again")
        print("If you want to exit input 0 or press CTRL+C")
        print("Or wait for timeout")
        print("==========================================================")

        chose_input = input("Choose input: 1 - client, 2 - server, 3 - switch: ")

    MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
    if chose_input == "1":  # Client Side
        if not switch_initiated and count_of_starts == 0:
            IP_SERVER = input("Enter server IP: ")
            PORT_SERVER = int(input("Enter server port: "))
            IP_CLIENT = get_ethernet_ip()
            print(f" CLIENT IP : {IP_CLIENT}")

        elif switch_initiated:
            IP_SERVER = IP_CLIENT[0]
            if count_of_switches == 1:
                PORT_SERVER = int(input("Enter server port: "))
                count_of_switches = 0

        # Create a UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (IP_SERVER, PORT_SERVER)

        file_or_text = input("Choose input: 1 - text, 2 - file, 3 - switch, 0 - exit: ")
        if file_or_text == "0":
            print("Exiting...")
            if client_socket is not None:
                client_socket.close()
            if server_socket is not None:
                server_socket.close()
            break
        elif file_or_text == "3":
            chose_input = "3"
            continue
        corrupt = input("Do you want to corrupt packets? (y/n): ")
        packet_data_size = int(input(f"Enter packet data size (MAX {MAX_DATA_SIZE}): "))
        if packet_data_size != "" and not packet_data_size > MAX_DATA_SIZE:
            MAX_DATA_SIZE = packet_data_size
        else:
            MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE

        if file_or_text == "1":  # =========================     TEXT     =========================
            try:
                # Send TEXT
                # print(f"file_or_text: {file_or_text}")
                message_body = bytes(input("Enter the message: "), 'utf-8')
                sequence_number = 0  # Example sequence number as 3 bytes
                sequence_bytes = int_to_3bytes(sequence_number)
                total_chunks = calculate_chunk_count(len(message_body), MAX_DATA_SIZE) - 1
                total_chunks_bytes = int_to_3bytes(total_chunks)

                # if sequence_number == 0:  # send init packet
                # crc = calculate_crc16("Init")
                crc = calculate_crc16(b"Init")
                header_init = CustomHeader(PACKET_TYPES.get("SYN"), sequence_bytes, total_chunks_bytes, crc)
                info_data = header_init.serialize() + b'text'
                response = send_packet(client_socket, info_data, server_address)
                print(f"Response: {response}")
                if response:
                    print("Connection Innitiated")
                    # sequence_number += 1
                else:
                    client_socket.close()
                    exit(1)
                for chunk in split_into_chunks(message_body, MAX_DATA_SIZE):

                    # Calculate the CRC for the chunk
                    crc = calculate_crc16(chunk)

                    # Create header for this chunk
                    if not (len(chunk) > MAX_DATA_SIZE - 1):
                        print("last packet, sending FIN")
                        fin_header = CustomHeader(PACKET_TYPES.get("FIN"), sequence_bytes, total_chunks_bytes, crc)
                        packet = fin_header.serialize() + chunk
                    else:
                        header = CustomHeader(PACKET_TYPES.get("DATA"), sequence_bytes, total_chunks_bytes, crc)
                        packet = header.serialize() + chunk

                    if sequence_number == 1 and corrupt == "y":
                        print("Corrupting packet")
                        corr_packet = corrupt_packet(packet)
                        # Send Corrupt packet
                        response = send_packet(client_socket, corr_packet, server_address)
                    else:
                        # send packet
                        response = send_packet(client_socket, packet, server_address)
                    if response is None:
                        print("Server not responding, closing connection...")
                        client_socket.close()
                        break
                    elif response is not None and int.from_bytes(response, byteorder='big') == PACKET_TYPES.get(
                                                                                                "ERROR"):
                        print("Error, Tryning Again...")
                        response = send_packet(client_socket, packet, server_address)


                    # Increment the sequence number
                    sequence_number = (sequence_number + 1) % (1 << 24)  # Ensure it wraps around at 2^24

                    # Convert the incremented sequence number to a 3-byte byte object
                    sequence_bytes = int_to_3bytes(sequence_number)

            except Exception as e:
                print(e)

            finally:

                print("Waiting for switch packet")
                try:

                    # server_address = (IP_SERVER, PORT_SERVER)
                    client_socket.settimeout(4)

                    response, _ = client_socket.recvfrom(1024)  # buffer for switch packet from server
                    if int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("CHANGE"):
                        client_socket.sendto(int.to_bytes(PACKET_TYPES.get("ACK"), length=1, byteorder='big'), (IP_SERVER, PORT_SERVER))
                        print("Switching...")
                        chose_input = "2"
                        client_socket.close()
                        switch_initiated = True
                        count_of_starts = 0
                        temp = IP_SERVER
                        IP_SERVER = IP_CLIENT[0]
                        IP_CLIENT = temp
                        temp = PORT_SERVER
                        PORT_SERVER = PORT_CLIENT
                        PORT_CLIENT = temp
                        count_of_switches = 1
                        continue
                except socket.timeout:
                    print("No switch packet received")
                    count_of_starts = 1
                    continue
                # print("Message sent successfully")
                # print(f" CLIENT IP : {IP_CLIENT}")
                # print(f" CLIENT PORT : {PORT_CLIENT}")
                # print(f" SERVER IP : {IP_SERVER}")
                # print(f" SERVER PORT : {PORT_SERVER}")
                # continue
                # finally:
            #     print("Closing socket")
            #     client_socket.close()
        else:  # =========================     File     =========================
            response = None
            try:
                # Input the file path
                file_path_input = input("Enter path to save the file: ")
                file_path = bytes(file_path_input+"|", 'utf-8')
                if len(file_path) > MAX_DATA_SIZE - 1:
                    print("File path too long")
                    exit(1)
                file_name_input = input("Enter path to file with file name: ")
                # print(f"file_name : {extract_filename(file_name_input)}")
                file_name = bytes(extract_filename(file_name_input), 'utf-8')
                # crate a sequence number in bytes that is 3 bytes long
                sequence_number = 0  # Example sequence number as 3 bytes
                sequence_bytes = int_to_3bytes(sequence_number)

                # Calculate the total number of chunks
                total_chunks = calculate_total_chunks(file_name_input, MAX_DATA_SIZE) - 1
                total_chunks_bytes = int_to_3bytes(total_chunks)
                if sequence_number == 0:  # send init packet
                    crc = calculate_crc16(b"Init")
                    header_init = CustomHeader(PACKET_TYPES.get("SYN"), sequence_bytes, total_chunks_bytes, crc)
                    info_data = header_init.serialize() + b'file' + file_path + file_name
                    response = send_packet(client_socket, info_data, server_address)
                    if response:
                        print("Connection Innitiated")
                        sequence_number += 1
                    else:
                        client_socket.close()
                        exit(1)

                for chunk in file_to_chunks(file_name_input, MAX_DATA_SIZE):
                    # Calculate the CRC for the chunk
                    crc = calculate_crc16(chunk)

                    # Create header for this chunk
                    if not (len(chunk) > MAX_DATA_SIZE - 1):
                        print("last packet, sending FIN")
                        fin_header = CustomHeader(PACKET_TYPES.get("FIN"), sequence_bytes, total_chunks_bytes, crc)
                        packet = fin_header.serialize() + chunk
                    else:
                        header = CustomHeader(PACKET_TYPES.get("DATA"), sequence_bytes, total_chunks_bytes, crc)
                        packet = header.serialize() + chunk
                    if sequence_number == 1 and corrupt == "y":
                        print("Corrupting packet")
                        corr_packet = corrupt_packet(packet)
                        # Send Corrupt packet
                        response = send_packet(client_socket, corr_packet, server_address)
                    else:
                        # send packet
                        response = send_packet(client_socket, packet, server_address)
                    if response is None:
                        print("Server not responding, closing connection...")
                        client_socket.close()
                        break
                    elif response is not None and int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("ERROR"):
                        print("Error, Tryning Again...")
                        response = send_packet(client_socket, packet, server_address)

                    # Increment the sequence number
                    sequence_number = (sequence_number + 1) % (1 << 24)  # Ensure it wraps around at 2^24

                    # Convert the incremented sequence number to a 3-byte byte object
                    sequence_bytes = int_to_3bytes(sequence_number)

                if response is not None:
                    print(f"File sent successfully = {total_chunks} packets")
            except Exception as e:
                print(e)
            finally:
                print("Waiting for switch packet")
                try:
                    client_socket.settimeout(4)

                    response, _ = client_socket.recvfrom(1024)  # buffer for switch packet from server
                    if int.from_bytes(response, byteorder='big') == PACKET_TYPES.get("CHANGE"):
                        client_socket.sendto(int.to_bytes(PACKET_TYPES.get("ACK"), length=1, byteorder='big'),
                                             (IP_SERVER, PORT_SERVER))
                        print("Switching...")
                        chose_input = "2"
                        client_socket.close()
                        switch_initiated = True
                        count_of_starts = 0
                        temp = IP_SERVER
                        IP_SERVER = IP_CLIENT[0]
                        IP_CLIENT = temp
                        temp = PORT_SERVER
                        PORT_SERVER = PORT_CLIENT
                        PORT_CLIENT = temp
                        count_of_switches = 1
                        continue
                except socket.timeout:
                    print("No switch packet received")
                    count_of_starts = 1
                    continue

    elif chose_input == "2":  # Server Side

        # Set up the server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        IP_SERVER = get_ethernet_ip()
        PORT_SERVER = int(input("Enter server port: "))

        server_address = (IP_SERVER, PORT_SERVER)
        server_socket.bind(server_address)
        print(f"Starting up on {server_address[0]} port {server_address[1]}")
        received_chunks = {}
        type_of_data = None
        file_path = "./"
        file_name = ""
        try:
            while True:

                server_socket.settimeout(15)
                print("\nWaiting to receive message...")
                packet, IP_CLIENT = server_socket.recvfrom(MAX_PACKET_SIZE)
                print(f"[+DEBUG+]Received {len(packet)} bytes from {IP_CLIENT[0]}")
                # Assuming the custom header is at the beginning of the packet
                header_data = packet[:HEADER_SIZE]  # 1 + 3 + 4 + 2 + 1 = 11 bytes for the header
                message_data = packet[HEADER_SIZE:]  # The rest is the payload
                # Deserialize the header
                header = CustomHeader.deserialize(header_data)

                # Calculate the CRC for the message data and verify it matches the received CRC
                received_crc = header.crc
                computed_crc = binascii.crc_hqx(message_data, 0)
                if header.command == 0x06:  # CHANGE packet
                    print("Change packet received")
                    server_socket.sendto(int.to_bytes(PACKET_TYPES.get("ACK"), length=1, byteorder='big'), IP_CLIENT)
                    print("Closing connection...")
                    server_socket.close()
                    switch_initiated = True
                    chose_input = "1"
                    break
                if header.command == 0x01:  # SYN packet
                    print("Init packet received")
                    type_of_data = message_data[0:4]
                    server_socket.sendto(int.to_bytes(PACKET_TYPES.get("ACK"), length=1, byteorder='big'), IP_CLIENT)
                    if type_of_data == b'file':
                        print("File transfer initiated")
                        file_info = bytes.decode(message_data[4:])
                        file_path = file_info.split("|")[0]
                        file_name = file_info.split("|")[1]
                        print(f"File path: {file_path}")
                        print(f"File name: {file_name}")
                        print(
                            f"Received header: Command={header.command}, "
                            f"Sequence Number={int.from_bytes(header.sequence_number, byteorder='big')}, "
                            f"Total Fragments={int.from_bytes(header.fragment_count, byteorder='big')}, "
                            f"CRC={header.crc:04x}, ")
                    continue

                if received_crc != computed_crc:  # CRC check
                    print("CRC check failed, packet corrupted.")
                    server_socket.sendto(int.to_bytes(PACKET_TYPES.get("ERROR"),
                                                      length=1, byteorder='big'), IP_CLIENT)
                else:
                    if header.command == 0x02:  # DATA packet
                        print("Data packet received")
                        # send back to client
                        server_socket.sendto(int.to_bytes(PACKET_TYPES.get("ACK"),
                                                          length=1, byteorder='big'), IP_CLIENT)
                    elif header.command == 0x04:  # FIN packet
                        print("FIN packet received")
                        # send back to client
                        server_socket.sendto(int.to_bytes(PACKET_TYPES.get("FINACK"),
                                                          length=1, byteorder='big'), IP_CLIENT)
                # Output the received header and data for demonstration purposes
                print(
                    f"Received header: Command={header.command}, "
                    f"Sequence Number={int.from_bytes(header.sequence_number, byteorder='big')}, "
                    f"Total Fragments={int.from_bytes(header.fragment_count, byteorder='big')}, "
                    f"CRC={header.crc:04x}, ")
                # print(f"Received data: {message_data}")

                received_chunks[int.from_bytes(header.sequence_number, byteorder='big')] = message_data

                # If the FIN packet is received, construct the file
                if header.command == 0x04 and bytes.decode(type_of_data) == "file":
                    try:
                        print("Constructing File")
                        with open(f'{file_path}{file_name}', 'wb') as file:
                            for seq in sorted(received_chunks.keys()):
                                file.write(received_chunks[seq])
                        file.close()
                        print("File constructed")
                        print(f"File saved at {file_path}{file_name}")
                        server_switch = input("Do you want to switch ? (y/n): ")
                        if server_switch == "y":
                            server_switch = ""
                            print("Switching... from server")
                            server_socket.sendto(int.to_bytes(PACKET_TYPES.get("CHANGE"), length=1, byteorder='big'),
                                                 IP_CLIENT)
                            response = server_socket.recvfrom(1024)
                            if response:
                                switch_initiated = True
                                count_of_switches = 1
                                chose_input = "1"
                                break
                    except Exception as e:
                        print(e)
                elif header.command == 0x04 and bytes.decode(type_of_data) == "text":
                    # print("Fin packet received, closing connection...")
                    full_text = []
                    for dt in received_chunks.values():
                        full_text.append(bytes.decode(dt))

                    print(f"Received data: {''.join(full_text)}")
                    server_switch = input("Do you want to switch ? (y/n): ")
                    if server_switch == "y":
                        server_switch = ""
                        print("Switching... from server")
                        server_socket.sendto(int.to_bytes(PACKET_TYPES.get("CHANGE"), length=1, byteorder='big'),
                                             IP_CLIENT)
                        response = server_socket.recvfrom(1024)
                        if response:
                            switch_initiated = True
                            count_of_switches = 1
                            chose_input = "1"
                            break
        except socket.timeout:
            print("Timeout, closing connection...")
            server_socket.close()
            switch_initiated = False
            count_of_starts = 0
            continue
        finally:
            pass
            # server_socket.close()

    elif chose_input == "3":  # Switch
        try:
            crc = calculate_crc16(b"Change")
            header_init = CustomHeader(PACKET_TYPES.get("CHANGE"), b"0", b"0", crc)
            info_data = header_init.serialize()
            response = send_packet(client_socket, info_data, (IP_SERVER, PORT_SERVER))
            if response:
                switch_initiated = True
                print("Change Innitiated")
                client_socket.close()
                chose_input = "2"
                temp = IP_SERVER
                IP_SERVER = IP_CLIENT[0]
                IP_CLIENT = temp
                temp = PORT_SERVER
                PORT_SERVER = PORT_CLIENT
                PORT_CLIENT = temp
                count_of_switches = 1
                continue
            elif response is None:
                print("Connection closed")
                client_socket.close()
                break
        except Exception as e:
            print(e)
            continue
    elif chose_input == "0":
        print("Exiting...")
        if client_socket is not None:
            client_socket.close()
        if server_socket is not None:
            server_socket.close()
        break
