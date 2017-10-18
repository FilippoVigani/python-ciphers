#! /usr/bin/env python3
import cipher
import cipherutils

"""
Implements encryption and decryption using the Data Encryption Standard (DES) algorithm as published by the National Institute of Standards and Technology (NIST).

This implementation is not official and is published only for educational purposes. Please refrain from using it for other purposes.

"""
__author__ = "Filippo Vigani"
__copyright__ = "Copyright 2017, Filippo Vigani"
__credits__ = ["Filippo Vigani"]
__license__ = "GPLv3"
__maintainer__ = "Filippo Vigani"
__email__ = "vigani.filippo@gmail.com"

class DES(cipher.Cipher):

	def run(bits_blocks, key, decrypt=False):
		result = []
		for block in bits_blocks:
			ip = DES.permute(block, DES.ip_table)
			L, R = (ip[:32], ip[32:])
			C, D = (None, None)

			K = [[] for i in range(16)]

			def iterate(L, R):
				return (R, DES.xor(L, DES.f(R,K[n])))

			for n in range(16): #generate all the keys and store them
				C, D, K[n] = DES.key_schedule(n, key, C, D)
				if not decrypt:
					L, R = iterate(L, R)

			if decrypt:
				for n in reversed(range(16)):
					L, R = iterate(L, R)

			preoutput = R + L
			ciphertext = DES.permute(preoutput, DES.iip_table)
			result.extend(ciphertext)

		return result

	def validate(plaintext, key):
		if not (isinstance(key, str) and len(key) == 8):
			raise "Key must be a 8 bytes long string."
		return (plaintext, key)

	def sanitize(plaintext, key):
		return (str(plaintext), key)

	def compose(plaintext, key):
		text_blocks = [plaintext[d:d+8] for d in range(0, len(plaintext), 8)]
		input_bits = [cipherutils.string_to_bits(block) for block in text_blocks]
		#TODO: fix blocks with <8 length
		return (input_bits, cipherutils.string_to_bits(key))

	def parse(output):
		return cipherutils.bits_to_string(output)

	def permute(bits, table):
		return [bits[pos - 1] for pos in table]

	def f(R, K):
		E = DES.expand(R, DES.e_box)
		X = DES.xor(K, E)
		S = DES.substitute(X, DES.s_box)
		P = DES.permute(S, DES.p_box)
		return P

	def key_schedule(n, key, C, D):
		if n == 0:
			pc1 = DES.permute(key, DES.pc1_table)
			C = pc1[:28]
			D = pc1[28:]
		C = DES.left_circular_shift(C, DES.number_of_left_shifts_by_iteration_number[n])
		D = DES.left_circular_shift(D, DES.number_of_left_shifts_by_iteration_number[n])
		K = DES.permute(C + D, DES.pc2_table)
		return (C, D, K)

	def left_circular_shift(bits, shift_count):
		return bits[shift_count:] + bits[:shift_count]

	def expand(bits, e_box):
		return DES.permute(bits, e_box)

	def xor(bits_list1, bits_list2):
		return [x ^ y for (x,y) in zip(bits_list1, bits_list2)]

	def substitute(bits, s_box):
		result = []
		for i in range(0,8):
			B = bits[i*6:i*6+6]
			row_bits = [B[0], B[5]]
			column_bits = B[1:5]
			row = DES.bits_to_int(row_bits)
			column = DES.bits_to_int(column_bits)
			result.extend(DES.int_to_bits(s_box[i][row][column], 4))
		return result

	def bits_to_int(bits):
		out = 0
		for bit in bits:
			out = (out << 1) | bit
		return out

	def int_to_bits(n, min_digits):
		res = [1 if digit=='1' else 0 for digit in bin(n)[2:]]
		return [0]*(min_digits - len(res)) + res

	ip_table = [58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7]

	iip_table = [40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25]

	pc1_table = [57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4]

	number_of_left_shifts_by_iteration_number = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

	pc2_table = [14, 17, 11, 24, 1, 5, 3, 28,
	15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32]

	e_box = [32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1]

	s_box = [
	[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], 
	[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], 
	[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
	[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

	[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
	[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
	[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
	[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

	[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
	[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
	[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
	[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

	[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
	[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
	[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
	[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
	 
	[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
	[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
	[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
	[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

	[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
	[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
	[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
	[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

	[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
	[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
	[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
	[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

	[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
	[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
	[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
	[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
	]

	p_box = [16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25]

if __name__ == '__main__':
	plaintext = "computer"
	print("Plaintext: {}".format(plaintext))
	ciphertext = DES.crypt(plaintext, "420blzit")
	print("Ciphertext: {}".format(ciphertext))
	output = DES.decrypt(ciphertext, "420blzit")
	print("Plaintext after decryption: {}".format(output))
