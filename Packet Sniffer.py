import socket
import os

#host to listen on 
host = "192.168.1.1"

#creating a raw socket and binding it to the public interface
if os.name == "nt":
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

#Collecting the IP Headers in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#if we are using windows, we need to send an IOCTL(Input Output Control) to setting up a promiscous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

#read in a single packet 
print sniffer.recvfrom(65565)

#if we are using the windows os we need to turn off the promiscous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.SIO_RCVALL_OFF)

										