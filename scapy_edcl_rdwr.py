from scapy.all import *

#	в ответных пакетах возможно некорректное отображение.
#	При использовании на возвращаемое значение show и hexdump - пакеты отображаются корректно
# 	так же при обращении к конкретной части конкретного хедера, данные так же отображаются корректно
class NoneResponseErr(Exception):
	def __str__(self):
		return "No response received for packet"
class NoneResponseWithMachineWrongLen(Exception):
	def __str__(self):
		return "\nNo response received for packet. Cause may be a packet size that isnt "\
			"division by 4 and executing of script on a physic microchip"

class edcl:
	IP_VER = 4
	IP_LEN = 5
	max_payloadsz =  456 #968 - max size from documentation
	seqnum_fieldsz = 0x3fff

	def __init__(self, macaddr_source, ipaddr_source, ipaddr_dest, iface_name):
		self.macaddr_dest = None
		self.macaddr_source = macaddr_source
		self.ipaddr_source = ipaddr_source
		self.ipaddr_dest = ipaddr_dest
		self.iface = iface_name
		self.counter = 0

		self.ETH_HEADER = Ether(
			dst = self.macaddr_dest,
			src = self.macaddr_source,
			type = ETH_P_IP
		)
		self.IP_HEADER = IP(
			version = self.IP_VER,
			ihl = self.IP_LEN,
			proto = IP_PROTOS.udp,
			src = self.ipaddr_source,
			dst = self.ipaddr_dest
		)
		self.UDP_HEADER = UDP(
			sport = 34944,
			dport = 39312
		)

	def __edcl_read_write(self, address, size, rdwr = 0, value = ''):
 		rdwr = bool(rdwr)
 		offset_addr = 0
 		last_response = b''

 		while size > 0:
 			edcl_data = 0
 			edcl_data |= self.counter << 18
 			edcl_data |= rdwr << 17
 			if size > self.max_payloadsz:
 				edcl_data |= self.max_payloadsz << 7
 				temp_value = value[offset_addr:offset_addr + self.max_payloadsz] * rdwr
 			else:
 				edcl_data |= size << 7
 				temp_value = value[offset_addr:] * rdwr

 			value_bytes = edcl_data.to_bytes(4, byteorder = "big")
 			packet = self.ETH_HEADER/self.IP_HEADER/self.UDP_HEADER/b'\x00\x00'/\
 					value_bytes/int.to_bytes(int.from_bytes(address, byteorder = "big")\
 					+ offset_addr, 4, "big")/temp_value

 			response = srp1(packet, iface = self.iface, timeout = 2)

 			if response == None and size % 4 != 0:
 				raise NoneResponseWithMachineWrongLen()

 			if response == None:
 				raise NoneResponseErr()

 			raw_external_counter = int.from_bytes(bytes(response[Raw])[2:4], "big")
 			external_counter = (raw_external_counter >> 2) & (self.seqnum_fieldsz)

 			if external_counter != self.counter:
 				self.counter = external_counter
 				continue
 			size -= self.max_payloadsz
 			offset_addr += self.max_payloadsz
 			self.counter += 1
 			if rdwr == 0:
 				last_response += bytes(response[Raw].load[10:])

 		return last_response

	def read(self, address, size):
		return self.__edcl_read_write(address, size)

	def write(self, address, size, value):
		return self.__edcl_read_write(address, size, 1, value)