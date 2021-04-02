from socket import *
import os
import sys
import struct
import time
import select
import binascii
import ipaddress
import statistics
# Should use stdev

ICMP_ECHO_REQUEST = 8


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



def receiveOnePing(mySocket, ID, timeout, destAddr, send_time):
    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return 0.0

        timeReceived = time.time()
        # print("This is the time received: " + str(timeReceived))
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start

        # Fetch the ICMP header from the IP packet
        unpacked_data = struct.unpack("BBHHH",recPacket[20:28])
        # print(unpacked_data)
        received_time = time.time()
        type, code, check_sum, packetid, seq = struct.unpack("BBHHH",recPacket[20:28])
        # print(type, code, check_sum, packetid, "icmp_seq =", seq)
        if(packetid == ID):
            version, type, length, ipid, flags, ttl, ipprotocol, ipchecksum, src_ip, dest_ip = struct.unpack("!BBHHHBBHII", recPacket[:20])
            # print(version, type, length, ipid, flags, ttl, ipprotocol, ipchecksum, str(ipaddress.IPv4Address(src_ip)), str(ipaddress.IPv4Address(dest_ip)))
            print("Reply from " + str(ipaddress.IPv4Address(src_ip)) + ": bytes=" + str(len(recPacket) - 28) + " time=" + str((received_time - send_time) * 1000.0) + "ms TTL=" + str(ttl))
            return (received_time - send_time) * 1000.0
        # Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return 0.0


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)


    header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    send_time = time.time()
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

    return send_time
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")


    # SOCK_RAW is a powerful socket type. For more details:   http://sockraw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    # print(mySocket)
    myID = os.getpid() & 0xFFFF  # Return the current process i
    # print(myID)
    send_time = sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr, send_time)
    # print(delay)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    pings = []
    total_time = 0.0
    packet_min = 0.0
    packet_max = 0.0
    dropped_packets = 0
    total_packets = 0
    # timeout=1 means: If one second goes by without a reply from the server,  	# the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    # Calculate vars values and return them
    #  vars = [str(round(packet_min, 2)), str(round(packet_avg, 2)), str(round(packet_max, 2)),str(round(stdev(stdev_var), 2))]
    # Send ping requests to a server separated by approximately one second
    for i in range(0, 4):
        total_packets += 1
        delay = doOnePing(dest, timeout)
        if delay != 0.0:
            pings.append(delay)
            # print("This is the delay: " + delay)
            total_time += delay
            if packet_min > delay:
                packet_min = delay
            if packet_max < delay:
                packet_max = delay
        else:
            dropped_packets += 1
        time.sleep(1)  # one second

    vars = [round(packet_min, 2), round(statistics.mean(pings), 2), round(packet_max, 2), round(statistics.stdev(pings), 2)]
    print("")
    print("--- " + host + " ping statistics ---")
    print(str(total_packets) + " packets transmitted, " + str((total_packets - dropped_packets)) + "packets received, " + str(round(dropped_packets/total_packets, 1)) + "% packet loss")
    # print(str(round(dropped_packets/total_packets, 1)) + "% packet loss")
    print("round-trip min/avg/max/stddev = " + str(round(packet_min, 2)) + "/" + str(round(statistics.mean(pings), 2)) + "/" + str(round(packet_max, 2)) + "/" + str(round(statistics.stdev(pings), 2)))
    # print(str(round(packet_min, 2)) + "/" + str(round(statistics.mean(pings), 2)) + "/" + str(round(packet_max, 2)) + "/" + str(round(statistics.stdev(pings), 2)))
    return vars

if __name__ == '__main__':
    # ping("google.co.il")
    # ping("127.0.0.1")
    ping("no.no.e")
