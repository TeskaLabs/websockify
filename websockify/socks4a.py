#!/usr/bin/env python2
import socket
import binascii

def to_hex_str(s):
	return ":".join("{:02x}".format(ord(c)) for c in s)

class SOCKS4A(object):

	def __init__(self, sock):
		self.sock = sock

	@staticmethod
	def create_msg_CONNECT(dest_port, dest_ip, user_id, remote_name):
		msg=bytearray()
		msg.append(4) # Version: 4
		msg.append(1) # SOCKS command: 1 (CONNECT)
		msg.extend(SOCKS4A.parse_port(dest_port)) # Remote port
		msg.extend(SOCKS4A.parse_ip(dest_ip)) # Remote IP
		msg.extend(bytearray(user_id)) # User ID
		msg.append(0)
		msg.extend(bytearray(remote_name)) # Remote name
		msg.append(0)
		return msg


	@staticmethod
	def parse_port(port):
		if port < 0 or port > 65535:
			raise RuntimeError("Destination port is must be between 0 and 65535")

		return bytearray.fromhex('{:02x}'.format(port))


	@staticmethod
	def parse_ip(ip):
		dest_ip_bytes = bytearray()
		try:
			ip_bytes = ip.split(".")
			if len(ip_bytes) > 4:
				raise
			for x in range(4):
				b = int(ip_bytes[x])
				if b < 0 or b > 255:
					raise
				dest_ip_bytes.append(b)
		except:
			raise RuntimeError("Invalid destination IP: {}".format(ip))
		return dest_ip_bytes


	def do_CONNECT(self, dest_port, dest_ip, user_id, remote_name):
		try:
			msg = SOCKS4A.create_msg_CONNECT(dest_port, dest_ip, user_id, remote_name)
			self.sock.send(msg)
			data = self.sock.recv(8)
			data_bytes = bytearray(data)
			if data_bytes[1] == 0x5a:
				return True
			else:
				return False
		except Exception as e:
			print(e)
			return False

def main():
	sock = socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(("127.0.0.1", 12367))

	socks4a = SOCKS4A(sock)
	if socks4a.do_CONNECT(
		dest_port=5900,
		dest_ip="0.0.0.1",
		user_id="",
		remote_name="remotename"):
		print "OK"
	else:
		print "ERROR"


if __name__ == '__main__':
	main()
