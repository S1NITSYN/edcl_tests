from sock_edcl_rdwr import *
from random import randint
import os

class tests:
	def __init__(self, ipaddr_dest, timeout = 2):
		self.ipaddr_dest = ipaddr_dest
		self.rdwr = edcl(self.ipaddr_dest)
		self.timeout = timeout

	# TODO: multithreat support to reduce copipasted code
	def __raw_send(self):
		with socket_handler(self.ipaddr_dest, self.rdwr.ports, self.timeout) as sock:
			while(True):
				edcl_data = 0
				edcl_data |= self.rdwr.counter << 18
				edcl_data |= 1 << 17
				edcl_data |= 4 << 7

				packet = b'\x00\x00' + edcl_data.to_bytes(4, byteorder = 'big') +\
						 b'\x00\x04\x00\x00' + b'\x01\x01\x01\x01'

				response = sock._send_data(packet)

				try:
					if response == None:
						raise RuntimeError("socket connection broken on transmit")
				except Exception as e:
					print(e)
					return

				chunk = sock._receive_data(self.rdwr.MAX_PAYLOADSZ)

				try:
					if chunk == None and size % 4 != 0:
						raise NoneResponseWithMachineWrongLen() 
					elif chunk == None:
						raise NoneResponseErr()
				except Exception as e:
					print(e)
					return

				raw_external_counter = int.from_bytes(bytes(chunk)[2:4], "big")
				external_counter = (raw_external_counter >> 2) & (self.rdwr.SEQNUM_FIELDSZ)

				if (external_counter != self.rdwr.counter):
					self.rdwr.counter = external_counter
					continue
				else:
					break
		return chunk

	def rd_wr_rd_test(self, address, sz, value):
		first_read = self.rdwr.read(address, sz)
		print(f"Результат первого чтения: {first_read}")
		self.rdwr.write(address, sz, value)
		second_read = self.rdwr.read(address, sz)
		if value == second_read:
			print("rd_wr_rd_test - OK")
			print(f"Результат второго чтения: {second_read}")
		else:
			print("rd_wr_rd_test - smth went wrong")

	def wr_file_with_execution_test(self, address, filepath, codeword):
		file = open(filepath, "rb")
		sz = os.path.getsize(filepath)
		payload = file.read(sz)
		self.rdwr.write(address, sz, payload)
		self.rdwr.write(address, 4, codeword)
		print(self.rdwr.read(address, sz))


	def stress_test(self, address, sz, value):
		iterator = 0
		while (iterator != 5000):
			self.rdwr.write(address, sz, value)
			self.rdwr.read(address, sz)
			iterator += 1

	def arp_wrong_ip_test(self): #search the opportunity to send arp request with an iface name
		sock = socket(family=AF_INET, type=SOCK_DGRAM, proto=IPPROTO_UDP)
		sock.bind(('', self.rdwr.ports))
		try:
			self.sock.connect(('192.168.1.47', self.rdwr.ports))
		except:
			print("arp_wrong_ip_test - OK")
		else:
			print("arp_wrong_ip_test - smth went wrong:")

	def edcl_with_wrong_ip_test(self, address, sz, value):
		with socket_handler('192.168.1.45', self.rdwr.ports, self.timeout) as sock:
			response = sock._send_data(b"shit")
			recv = sock._receive_data(sz)
			if recv == None:
				print("edcl_with_wrong_ip_test - OK")
			else:
				print("edcl_with_wrong_ip_test - response was taken or smth else; error")

	def zero_len_for_replies_to_write_test(self):
		res = self.__raw_send()
		if (((int.from_bytes(bytes(res)[3:6], byteorder = 'big') >> 7) & 0x3FF) == 0):
			print("zero_len_for_replies_to_write_test - OK")
		else:
			print("zero_len_for_replies_to_write_test - reply len != 0; error")
			print(res)

	def len_for_replies_to_read_test(self, sz, address):
		with socket_handler(self.ipaddr_dest, self.rdwr.ports, self.timeout) as sock:
			while(True):
				edcl_data = 0
				edcl_data |= self.rdwr.counter << 18
				edcl_data |= 0 << 17
				edcl_data |= sz << 7

				packet = b'\x00\x00' + edcl_data.to_bytes(4, byteorder = 'big') + address

				response = sock._send_data(packet)

				if response == 0:
					raise RuntimeError("socket connection broken on transmit")

				try:
					if response == None:
						raise RuntimeError("socket connection broken on transmit")
				except Exception as e:
					print(e)
					return

				chunk = sock._receive_data(self.rdwr.MAX_PAYLOADSZ)

				try:
					if chunk == None and size % 4 != 0:
						raise NoneResponseWithMachineWrongLen() 
					elif chunk == None:
						raise NoneResponseErr()
				except Exception as e:
					print(e)
					return

				raw_external_counter = int.from_bytes(bytes(chunk)[2:4], "big")
				external_counter = (raw_external_counter >> 2) & (self.rdwr.SEQNUM_FIELDSZ)

				if (external_counter != self.rdwr.counter):
					self.rdwr.counter = external_counter
					continue
				else:
					break
		res = chunk
		full_packetsz = int(sz / self.rdwr.MAX_PAYLOADSZ) * self.rdwr.MAX_PAYLOADSZ
		sz -= full_packetsz
		if (((int.from_bytes(bytes(chunk)[3:6], byteorder = 'big') >> 7) & 0x3FF) == sz):
			print("len_for_replies_to_read_test - OK")
		else:
			print("len_for_replies_to_read_test - incorrect reply len; error")
			print(res)

	def diff_seq_nums_to_send_test(self, times, address): #to check
		disposable = times
		max_seq_num = 16383
		main = 0
		with socket_handler(self.ipaddr_dest, self.rdwr.ports, self.timeout) as sock:
			while(times != 0):
				edcl_data = 0
				integer = randint(1, max_seq_num)
				if(integer == main):
					integer = randint(1, max_seq_num)
				edcl_data |= integer << 18
				edcl_data |= 4 << 7
				packet = b'\x00\x00' + edcl_data.to_bytes(4, byteorder = 'big') + address
				response = sock._send_data(packet)

				try:
					if response == None:
						raise RuntimeError("socket connection broken on transmit")
				except Exception as e:
					print(e)
					return

				chunk = sock._receive_data(self.rdwr.MAX_PAYLOADSZ)

				try:
					if chunk == None and size % 4 != 0:
						raise NoneResponseWithMachineWrongLen() 
					elif chunk == None:
						raise NoneResponseErr()
				except Exception as e:
					print(e)
					return

				if(times == disposable):
					main = (int.from_bytes(bytes(chunk)[2:4], "big") >> 2)
				times -= 1
			else:
				print("diff_seq_nums_to_send_test - OK")
				return
			print("diff_seq_nums_to_send_test - the response was taken with a incorrect sequence number; error")
			print(res)