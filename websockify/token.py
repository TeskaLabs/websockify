# /usr/bin/env python
#
# Copyright 2017 Miloslav Pavelka
#
# Licensed under BSD-3-Clause
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import time, hashlib


class Token(object):
	"""Universal Token API for generating and validating access tokens.
	"""

	def __init__(self, secret=''):
		self.secret = secret
		self.reset()



	@staticmethod
	def append(a, b):
		a = str(a)
		b = str(b)
		return a + ('' if a == '' else '_') + b



	def export(self, signed=True):
		""" Exports the token to a string

			Only signed token can be exported
			:return string: The token
		"""
		token = Token.tokenize_data(self.data)
		token = Token.append(token, Token.timestamp_to_str(self.timestamp))
		if not signed:
			return token

		if self.signature is None:
			raise RuntimeError('Can\'t export unsigned token.')
		token = token + '.' + self.signature

		return token



	@staticmethod
	def gen_signature(data, timestamp, secret=''):
		""" Generates a signature

			:return string: the signature
		"""
		token = ''
		token = Token.append(token, Token.tokenize_data(data))
		token = Token.append(token, Token.timestamp_to_str(timestamp))
		return hashlib.sha224(secret+token).hexdigest()



	def get_data(self):
		""" Returns token's data

			:return list: The data list
		"""
		return self.data



	def get_data_at_index(self, i):
		""" Reads the token's data

			:param integer index: The index of token's data
			:return string: The data
		"""
		data = self.get_data()
		return data[i]



	def parse(self, token):
		""" Parses string token

			:param string token:
		"""
		try:
			token = str(token)
		except: raise ValueError('Token contains non-ASCII characters.')

		# Split data and signature
		parts_s = token.split('.')
		if len(parts_s) < 2:
			raise ValueError('Unrecognized token structure.')
		data = '.'.join(parts_s[:-1])
		self.signature = parts_s[-1]

		# Split custom data and timestamp
		parts_d = data.split('_')
		if len(parts_d) < 2:
			raise ValueError('Unrecognized token structure.')
		self.data = parts_d[:-1]
		self.timestamp = float(parts_d[-1])
		


	def push(self, data):
		""" Adds data to the token
		"""
		self.data.append(str(data))



	def reset(self):
		""" Reset Token
		"""
		self.data = []
		self.timestamp = None
		self.signature = None



	def sign(self):
		""" Generates and stores token signature

			If timestamp is not stored yet, it gets generated and stored too

			
		"""
		if self.timestamp is None:
			self.set_timestamp()
		self.signature = Token.gen_signature(self.data, self.timestamp, self.secret)


	def set_timestamp(self, timestamp=None):
		""" Timestamp setter

			:param float timestamp: Optional timestamp (default time.time())
		"""
		self.timestamp = timestamp if timestamp is not None else time.time()


	@staticmethod
	def timestamp_to_str(timestamp):
		""" Generates a timestamp string

			:param float timestamp:
		"""
		return str('{0:.2f}'.format(timestamp))



	@staticmethod
	def tokenize_data(data=None):
		""" Implodes data to a string

			:param list data: the data array
			:return string: token string
		"""
		token = ''
		for x in data:
			token = Token.append(token, x)
		return token



	def validate(self, max_age=1800.0):
		""" Validates the token

			:param float max_age: Maximum token age (default: 1800.0 = 30 minutes)
			:throws InvalidTokenException: if age exceeds max_age
			:throws TokenIntegrityException: if signature doesn't match expected value
		"""

		# Validity
		if self.timestamp + max_age < time.time():
			raise InvalidTokenException()
		# Integrity
		if self.signature != Token.gen_signature(self.data, self.timestamp, self.secret):
			raise TokenIntegrityException()



# Exceptions

class InvalidTokenException(Exception):
	pass

class TokenIntegrityException(Exception):
	pass



# Tests
import unittest

class TestToken(unittest.TestCase):

	def setUp(self):
		self.token = Token()

	def test_append(self):
		self.assertEquals(Token.append('test', 'test2'), 'test_test2')
		self.assertEquals(Token.append('', 'test2'), 'test2')


	def test_export(self):
		self.token.parse('test_1487063344.58_invalidsignature')
		token = self.token.export()
		self.assertEquals(token, 'test_1487063344.58_invalidsignature')

	def test_gen_signature(self):
		self.assertIsInstance(Token.gen_signature(
			data=['test'],
			timestamp=1487063344.58), str)

	def test_get_data(self):
		pass

	def test_get_data_at_index(self):
		self.token.data = ['test', 'test2']
		self.assertEquals(self.token.get_data_at_index(1), 'test2')

	def test_parse(self):
		self.token.parse('test_1487063344.58_invalidsignature')
		self.assertEquals(self.token.data, ['test'])
		self.assertEquals(self.token.timestamp, 1487063344.58)
		self.assertEquals(self.token.signature, 'invalidsignature')

	def test_push(self):
		self.token.push('test')
		self.token.push('test2')
		self.assertEquals(self.token.data, ['test', 'test2'])

	def test_reset(self):
		pass

	def test_sign(self):
		self.token.sign()
		self.assertIsNotNone(self.token.signature)

	def test_set_timestamp(self):
		self.token.set_timestamp()
		self.assertIsNotNone(self.token.timestamp)

	def test_timestamp_to_str(self):
		ret = Token.timestamp_to_str(123.333324242)
		self.assertEquals(ret, '123.33')

	def test_tokenize_data(self):
		ret = Token.tokenize_data(['test', 'test2'])
		self.assertEquals(ret, 'test_test2')

	def test_validate(self):
		# Test validity failure
		self.token.set_timestamp(time.time()-2000.0)
		self.token.sign()
		with self.assertRaises(InvalidTokenException):
			self.token.validate()

		# Test integrity failure
		self.token.set_timestamp()
		self.token.signature = 'invalidsignature'
		with self.assertRaises(TokenIntegrityException):
			self.token.validate()

		# Test valid certificate
		self.token.sign()
		self.token.validate()


if __name__ == '__main__':
    unittest.main()

