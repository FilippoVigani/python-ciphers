

class Cipher():
	"""Encrypts the message using the specified key"""
	@classmethod
	def crypt(cls, plaintext, key):
		plaintext, key = cls.validate(plaintext, key)
		plaintext, key = cls.sanitize(plaintext, key)
		inputtext, inputkey = cls.compose(plaintext, key)
		ciphertext = cls.parse(cls.run(inputtext, inputkey))
		return ciphertext

	"""Descrypts the message using the specified key"""
	@classmethod
	def decrypt(cls, ciphertext, key):
		ciphertext, key = cls.validate(ciphertext, key)
		ciphertext, key = cls.sanitize(ciphertext, key)
		inputtext, inputkey = cls.compose(ciphertext, key)
		return cls.parse(cls.run(inputtext, inputkey, decrypt=True))

	"""checks if the input meets the algorithm criteria"""
	def validate(plaintext, key):
		raise NotImplementedError("Input validation not implemented")

	"""modifies the input to ensure that it is valid"""
	def sanitize(plaintext, key):
		raise NotImplementedError("Input sanitization not implemented")

	"""modifies the input to a suitable data type (e.g. string to list of bits)"""
	def compose(plaintext, key):
		raise NotImplementedError("Input composition not implemented")

	"""modifies the output so that it's in an intelligible form (e.g. list of bits to hex)"""
	def parse(output):
		raise NotImplementedError("Output parsing not implemented")

	"""executes the algorithm with the matching input and key. If decrypt is True, then decrpytion is ran."""
	def run(input, key, decrypt=False):
		raise NotImplementedError("Encryption/Decryption not implemented")
