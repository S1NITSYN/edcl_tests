from socket import *

#	в ответных пакетах возможно некорректное отображение.
#	При использовании на возвращаемое значение show и hexdump - пакеты отображаются корректно
# 	так же при обращении к конкретной части конкретного хедера, данные так же отображаются корректно
class NoneResponseErr(Exception):
	def __str__(self):
		return "\nNo response received for packet"
class NoneResponseWithMachineWrongLen(Exception):
	def __str__(self):
		return "\nNo response received for packet. Cause may be a packet size that isnt "\
			"division by 4 and executing of script on a physic microchip"
class NoneTransmit(Exception):
	def __str__(self):
		return "\nsocket connection broken on transmit"

class socket_handler:
	def __init__(self, ipaddr_dest, port, timeout):
		self.ipaddr_dest = ipaddr_dest
		self.port = port
		self.sock = socket(family=AF_INET, type=SOCK_DGRAM, proto=IPPROTO_UDP)
		self.sock.settimeout(timeout)

	def __enter__(self):
		self.sock.bind(('', self.port))
		self.sock.connect((self.ipaddr_dest, self.port))
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.sock.close()

	def _send_data(self, data):
		try:
			return self.sock.send(data)
		except Exception as e:
			print(e)
			return None

	def _receive_data(self, size):
		try:
			return self.sock.recv(size)
		except Exception as e:
			print(e)
			return None

class edcl:
	IP_VER = 4
	IP_LEN = 5
	MAX_PAYLOADSZ =  456 #968 - max size from documentation
	SEQNUM_FIELDSZ = 0x3fff

	def __init__(self, ipaddr_dest, timeout=2):
		self.ipaddr_dest = ipaddr_dest
		self.counter = 0
		self.ports = 34944 # FIXME: can be occupied
		self.timeout = timeout

	def __edcl_read_write(self, address, size, rdwr = 0, value = b''):
		rdwr = bool(rdwr)
		offset_addr = 0
		last_response = b''

		with socket_handler(self.ipaddr_dest, self.ports, self.timeout) as sock:
			while size > 0:
				edcl_data = 0
				edcl_data |= self.counter << 18
				edcl_data |= rdwr << 17
				if size > self.MAX_PAYLOADSZ:
					edcl_data |= self.MAX_PAYLOADSZ << 7
					temp_value = value[offset_addr:offset_addr + self.MAX_PAYLOADSZ] * rdwr
				else:
					edcl_data |= size << 7
					temp_value = value[offset_addr:] * rdwr

				value_bytes = b'\x00\x00' + edcl_data.to_bytes(4, byteorder = "big") + \
						 	  int.to_bytes(int.from_bytes(address, byteorder = "big") + \
						 	  offset_addr, 4, "big") + temp_value

				sizeof_sent_bytes = sock._send_data(value_bytes)
				try:
					if sizeof_sent_bytes == 0:
						raise NoneTransmit()
				except Exception as e:
					print(e)
					return

				chunk = sock._receive_data(self.MAX_PAYLOADSZ)
				try:
					if chunk == None and size % 4 != 0:
						raise NoneResponseWithMachineWrongLen() 
					elif chunk == None:
						raise NoneResponseErr()
				except Exception as e:
					print(e)
					return
					

				raw_external_counter = int.from_bytes(bytes(chunk)[2:4], "big")
				external_counter = (raw_external_counter >> 2) & (self.SEQNUM_FIELDSZ)

				if external_counter != self.counter:
					self.counter = external_counter
					continue
				size -= self.MAX_PAYLOADSZ
				offset_addr += self.MAX_PAYLOADSZ
				self.counter += 1
				if rdwr == 0:
					last_response += bytes(chunk)[10:]
		return last_response


	def read(self, address, size):
		return self.__edcl_read_write(address, size)

	def write(self, address, size, value):
		return self.__edcl_read_write(address, size, 1, value)
