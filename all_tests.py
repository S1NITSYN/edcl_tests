from scapy_edcl_rdwr import *
from random import randint

class tests:
	def __init__(self, macaddr_source, ipaddr_source, ipaddr_dest, iface_name):
		self.macaddr_source = macaddr_source
		self.ipaddr_source = ipaddr_source
		self.ipaddr_dest = ipaddr_dest
		self.iface = iface_name
		self.rdwr = edcl(self.macaddr_source, self.ipaddr_source, self.ipaddr_dest, self.iface)

	#todo:
	#multithreat support to reduce copipasted code
	def __raw_send(self):
		while(True):
			edcl_data = 0
			edcl_data |= self.rdwr.counter << 18
			edcl_data |= 1 << 17
			edcl_data |= 4 << 7

			value_bytes = edcl_data.to_bytes(4, byteorder = 'big')
			packet = self.rdwr.ETH_HEADER/self.rdwr.IP_HEADER/self.rdwr.UDP_HEADER/b'\x00\x00'/\
					value_bytes/b'\x00\x04\x00\x00'/b'\x01\x01\x01\x01'

			response = srp1(packet, iface = self.rdwr.iface, timeout = 2)

			raw_external_counter = int.from_bytes(bytes(response[Raw])[2:4], "big")
			external_counter = (raw_external_counter >> 2) & (self.rdwr.seqnum_fieldsz)

			if (external_counter != self.rdwr.counter):
				self.rdwr.counter = external_counter
				continue
			else:
				break
		return response

	def rd_wr_rd_test(self, address, sz, value):
		first_read = self.rdwr.read(address, sz)
		print(f"Результат первого чтения: {first_read}")
		self.rdwr.write(address, sz, value)
		second_read = self.rdwr.read(address, sz)
		if value == second_read:
			print(f"Результат второго чтения: {second_read}")
			print("rd_wr_rd_test - OK")
		else:
			print("rd_wr_rd_test - smth went wrong")

	def big_wr_rd_test(self, address, sz, value):
		self.rdwr.write(address, sz, value)
		big_rd = self.rdwr.read(address, sz)
		full_packets = int(sz / self.rdwr.max_payloadsz) * self.rdwr.max_payloadsz
		sz -= full_packets
		if(big_rd == value):
			print("big_wr_rd_test - OK")
		else:
			print(big_rd)
			print("big_wr_rd_test - smth went wrong")

	def wr_file_with_execution_test(self, address, filepath, codeword):
		file = open(filepath, "rb")
		sz = os.path.getsize(filepath)
		payload = file.read(sz)
		self.rdwr.write(address, sz, payload)
		self.rdwr.write(address, 4, codeword)
		print(self.rdwr.read(address, sz))


	def stress_test(self, address, sz, value):
		iterator = 0
		while (iterator != 10000):
			self.rdwr.write(address, sz, value)
			self.rdwr.read(address, sz)
			iterator += 1

	def broadcast_no_ans_test(self, address, sz, value):
		self.rdwr.ETH_HEADER.dst = 'ff:ff:ff:ff:ff:ff'
		try:
			response = self.rdwr.write(address, sz, value)
		except:
			print("broadcast_no_ans_test - OK")
		else:
			print(response)
			print("broadcast_no_ans_test - smth went wrong")

	def arp_wrong_ip_test(self): #search the opportunity to send arp request with an iface name
		response, sec = arping('192.168.1.47')
		if(len(response) == 0):
			print("arp_wrong_ip_test - OK")
		else:
			print("arp_wrong_ip_test - smth went wrong:")
			print(response, sec)
		return 1

	def edcl_with_wrong_ip_test(self, address, sz, value):
		self.rdwr.IP_HEADER.src = 1
		try:
			response = self.rdwr.write(address, sz, value)
		except:
			print("edcl_with_wrong_ip_test - OK")
		else:
			print("edcl_with_wrong_ip_test - response was taken or smth else; error")

	def protocol_other_then_ip_test(self, address, sz, value):
		self.rdwr.ETH_HEADER.type = 1
		try:
			response = self.rdwr.write(address, sz, value)
		except:
			print("protocol_other_then_ip_test - OK")
		else:
			print("protocol_other_then_ip_test - response was taken or smth else; error")

	def edcl_with_wrong_verlen_test(self, address, sz, value):
		self.rdwr.IP_HEADER.version = 1
		self.rdwr.IP_HEADER.ihl = 1
		try:
			response = self.rdwr.write(address, sz, value)
		except:
			print("edcl_with_wrong_verlen_test - OK")
		else:
			print("edcl_with_wrong_verlen_test - response was taken or smth else; error")

	def edcl_with_tcp_test(self, address, sz, value):
		self.rdwr.IP_HEADER.proto = 6
		TCP_HEADER = TCP(
			sport = randint(1, 100),
			dport = randint(1, 100),
		)
		self.rdwr.UDP_HEADER = TCP_HEADER
		try:
			res = self.rdwr.write(address, sz, value)
		except:
			print("edcl_with_tcp_test - OK")
		else:
			print("edcl_with_tcp_test - response was taken or smth else; error")
			print(res)


	def same_port_numbers_test(self, sport, dport):
		self.rdwr.UDP_HEADER.sport = sport
		self.rdwr.UDP_HEADER.dport = dport
		res = __raw_send()

		if(sport == res[UDP].sport == res[UDP].dport):
			print("same_port_numbers_test - OK")
		else:
			print("same_port_numbers_test - UDP ports are not the same; error")
			print(res)

	def miss_udp_checksum_test(self):
		self.rdwr.UDP_HEADER.chksum = randint(1, 100)
		res = self.__raw_send()
		if(res[UDP].chksum == 0):
			print("missing_udp_checksum_test - OK")
		else:
			print("missing_udp_checksum_test - UDP checksum != 0; error")
			print(res)

	def zero_len_for_replies_to_write_test(self):
		res = self.__raw_send()
		if (((int.from_bytes(bytes(res[Raw].load)[3:6], byteorder = 'big') >> 7) & 0x3FF) == 0):
			print("zero_len_for_replies_to_write_test - OK")
		else:
			print("zero_len_for_replies_to_write_test - reply len != 0; error")
			print(res)

	def len_for_replies_to_read_test(self, sz, address):
		while(True):
			edcl_data = 0
			edcl_data |= self.rdwr.counter << 18
			edcl_data |= 0 << 17
			edcl_data |= sz << 7

			value_bytes = edcl_data.to_bytes(4, byteorder = 'big')
			packet = self.rdwr.ETH_HEADER/self.rdwr.IP_HEADER/self.rdwr.UDP_HEADER/b'\x00\x00'/\
					value_bytes/address

			response = srp1(packet, iface = self.rdwr.iface, timeout = 2)

			raw_external_counter = int.from_bytes(bytes(response[Raw])[2:4], "big")
			external_counter = (raw_external_counter >> 2) & (self.rdwr.seqnum_fieldsz)

			if (external_counter != self.rdwr.counter):
				self.rdwr.counter = external_counter
				continue
			else:
				break
		res = response
		full_packets = int(sz / self.rdwr.max_payloadsz) * self.rdwr.max_payloadsz
		sz -= full_packets
		if (((int.from_bytes(bytes(res[Raw].load)[3:6], byteorder = 'big') >> 7) & 0x3FF) == sz):
			print("len_for_replies_to_read_test - OK")
		else:
			print("len_for_replies_to_read_test - incorrect reply len; error")
			print(res)

	def diff_seq_nums_to_send_test(self, times, address):
		disposable = times
		max_seq_num = 16383
		main = 0
		while(times != 0):
			edcl_data = 0
			integer = randint(1, max_seq_num)
			if(integer == main):
				integer = randint(1, max_seq_num)
			edcl_data |= integer << 18
			edcl_data |= 4 << 7
			value_bytes = edcl_data.to_bytes(4, byteorder = 'big')
			packet = self.rdwr.ETH_HEADER/self.rdwr.IP_HEADER/self.rdwr.UDP_HEADER/b'\x00\x00'/value_bytes/address
			res = srp1(packet, iface = self.rdwr.iface, timeout = 5)
			if(times == disposable):
				main = (int.from_bytes(bytes(res[Raw].load)[2:4], byteorder = 'big') >> 2)
			times -= 1
		else:
			print("diff_seq_nums_to_send_test - OK")
			return
		print("diff_seq_nums_to_send_test - the response was taken with a incorrect sequence number; error")
		print(res)

	def moreless_than_968_byte_test(self, address, sz):#fix
		self.rdwr.max_payloadsz = sz
		try:
			self.rdwr.write(address, sz, sz * b"1")
		except:
			print("more_than_968_byte_test - OK")
		else:
			print("more_than_968_byte_test - max size of 1 packet exceeded 968 byte; err")