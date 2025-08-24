import hmac
import hashlib
import binascii

key_hex_string = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
message_string = "Hi There"

key = binascii.unhexlify(key_hex_string)
message = message_string.encode("utf-8")

hmac_obj = hmac.new(key, message, hashlib.md5)
hmac_digest = hmac_obj.hexdigest()

print("Key: ", key_hex_string)
print("Message: ", message_string)
print("HMAC-SHA256 Digest: ", hmac_digest)


"""
Test Vectors (Trailing '\0' of a character string not included in test):

  key =         0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
  key_len =     16 bytes
  data =        "Hi There"
  data_len =    8  bytes
  digest =      0x9294727a3638bb1c13f48ef8158bfc9d

  key =         "Jefe"
  data =        "what do ya want for nothing?"
  data_len =    28 bytes
  digest =      0x750c783e6ab0b503eaa86e310a5db738
  """