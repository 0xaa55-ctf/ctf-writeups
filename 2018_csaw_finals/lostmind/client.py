import socket
from Crypto.Util.number import bytes_to_long, long_to_bytes

from Crypto.Util.number import getRandomInteger, GCD, inverse, getPrime

from pprint import pprint

import operator
import sys

magic = 38

flag = []
LENGTH = 1



for OFFSET in range(int(sys.argv[1]), int(sys.argv[2])):
	dist_map = {}

	for m in range(30):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('crypto.chal.csaw.io', 1003))


		weird = (
		            '====================================\n'
		            '1. encrypt\n'
		            '2. decrypt\n'
		            '====================================\n'
		        )

		weird2 = 'encrypted flag: '

		weird3 = 'input:'

		weird4 = 'you got 90 rounds to go'

		def get_enc_flag():

			enc_flag_msg = s.recv(4096).replace(weird2, '').replace(weird4, '').replace(weird3, '').replace(weird, '').strip()
			
			return int(enc_flag_msg, 16)

		def send_long(n):
			s.sendall(long_to_bytes(n))

		def get_menu():
			s.recv(4096)

		def send_menu_choice(c):
			s.sendall('%d\n' % c)

		def get_enc_msg(n):
			send_menu_choice(1)
			d = s.recv(4096)

			while 'input:' not in d:
				d = s.recv(4096)

			send_long(n)

			msg = s.recv(4096)

			msg = msg.replace(weird, '').replace(weird2, '').replace(weird3, '').strip()

			return int(msg.split('\n')[0], 16)

		def get_dec_msg(n):
			send_menu_choice(2)

			d = s.recv(4096)

			while 'input:' not in d:
				d = s.recv(4096)

			send_long(n)

			msg = s.recv(4096)

			# print msg

			return int(msg.split('\n')[0].replace(weird, '').strip(), 16)


		def find_n():
			a = get_enc_msg(2)
			a2 = get_enc_msg(4)
			b = get_enc_msg(5)
			b2 = get_enc_msg(25)
			c = get_enc_msg(7)
			c2 = get_enc_msg(49)

			n1 = GCD(a ** 2 - a2, b ** 2 - b2)
			n2 = GCD( a ** 2 - a2, c ** 2 - c2)
			n = GCD(n1, n2)
			return n, a

		# send offset length
		s.sendall('%d,%d\n' % (OFFSET, LENGTH))

		get_menu()

		# get flag
		enc_flag = get_enc_flag()

		n, _2e = find_n()

		L = 0
		U = n / (1 << magic)

		_2ei = pow(_2e, magic, n)

		for i in range(magic, magic + 84):
			_2ei = (_2ei * _2e) % n

			dec = get_dec_msg((enc_flag * _2ei) % n)
			if dec & 1:
				L = (L+U)/2
			else:
				U = (L+U)/2

			if (U & (0xff << 122*8)) >> 122*8 == (L & (0xff << 122*8)) >> 122*8:
				break

		ub = (U & (0xff << 122*8)) >> 122*8
		lb = (L & (0xff << 122*8)) >> 122*8

		if ub == lb:
			if ub in dist_map.keys():
				dist_map[ub] += 1

				if dist_map[ub] >= 4:
					break

			else:
				dist_map[ub] = 1
		else:
			pass

		s.close()

	flag.append(max(dist_map.iteritems(), key=operator.itemgetter(1))[0])


pprint(flag)
