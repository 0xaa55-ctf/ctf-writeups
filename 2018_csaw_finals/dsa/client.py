import binascii
import json
import hashlib

import requests as req
from randcracker import RandCrack

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

base_url = 'http://crypto.chal.csaw.io:1000/'


def get_random_from_server():
	return req.get(base_url + 'forgotpass').text.split('/')[-1]


def get_public_key():
	return json.loads(req.get(base_url + 'public_key').text)


def server_sign(message):
	return json.loads(req.get(base_url + 'sign/' + message).text)


def get_challenge():
	return req.get(base_url + 'challenge').text


def server_capture(challenge, signature):
	return req.post(base_url + 'capture', {'challenge': challenge, 'signature': signature}).text


random_numbers = []


print '[-] fetching public key from server'
public_key = get_public_key()
g, p, q = public_key['g'], public_key['p'], public_key['q']


print '[-] fetching random numbers from server'
for i in range(312):
	response = get_random_from_server()
	r1, r2 = response[:8], response[8:]

	random_numbers.append(int(r2, 16))	
	random_numbers.append(int(r1, 16))

print '[-] submitting numbers to rand cracker'
rc = RandCrack()
for n in random_numbers:
	rc.submit(n)

prediction = rc.predict_getrandbits(64)
real = int(get_from_server(), 16)
print '[-] testing prediction {} against server {}'.format(prediction, real)

assert prediction == real
print '[+] prediction seems good!'

# k used during sign
predicted_k = rc.predict_randrange(2, q)

# sign w/ server
challenge = get_challenge()
print '[-] challenge=%s' % challenge

signed_response = server_sign(challenge)
r, s = signed_response['r'], signed_response['s']
h = int(hashlib.sha1(challenge).digest().encode('hex'), 16)

print '[-] r=%d' % r
print '[-] s=%d' % s
print '[-] h=%d' % h

# get private key x
x = ((s * predicted_k) - h) * _modinv(pow(g, predicted_k, p) % q, q) % q

print '[+] x=%d' % x

# create signature with sha 256
correct_h = int(hashlib.sha256(challenge).digest().encode('hex'), 16)
correct_s = _modinv(predicted_k, q) * (correct_h + r * x) % q
fake_signature = encode_dss_signature(r, correct_s).encode('hex')
print '[+] flag=%s' % server_capture(challenge, fake_signature)