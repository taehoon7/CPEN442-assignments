import sys
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes, random

G_DH = 3
P_DH = 29
CLOCK_SKEW_S = 5

class SecurityError(Exception):
    pass

class Protocol:
    # Initializer (Called from app.py)
    def __init__(self):
        self._key = None
        self._dh_exp = None

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self, sockname, secret):

        (hostname, port) = sockname
        hostname_segments = hostname.split('.')
        ip = bytes()
        for num in hostname_segments:
            ip += int(num).to_bytes(1, sys.byteorder)
        port = port.to_bytes(2, sys.byteorder)
        identifier = (ip + port)

        if self._dh_exp is None:
            self._dh_exp = random.randint(1, G_DH - 1)
            dh_value = pow(G_DH, self._dh_exp, P_DH).to_bytes(4, sys.byteorder)
        else:
            dh_value = pow(G_DH, self._dh_exp, P_DH).to_bytes(4, sys.byteorder)
            self._dh_exp = None

        h = SHA256.new()
        h.update(secret.encode())
        hashed_secret = h.digest()

        timestamp = int(time.time()).to_bytes(4, sys.byteorder)

        iv = get_random_bytes(16)
        cipher = AES.new(hashed_secret, AES.MODE_CBC, iv=iv)
        padded = timestamp + dh_value
        while sys.getsizeof(padded) % 16 != 1:
            padded += b'\x00'
        encrypted = cipher.encrypt(padded)

        identifier_bytes = identifier.to_bytes((identifier.bit_length() + 7) // 8)
        timestamp_bytes = timestamp.to_bytes((timestamp.bit_length() + 7) // 8)
        dh_value_bytes = dh_value.to_bytes((dh_value.bit_length() + 7) // 8)

        hash_input = identifier_bytes + timestamp_bytes + dh_value_bytes
        # Need to pad the message before hashing so the hash will match what the receiver sees
        while (sys.getsizeof(hash_input) + 32) % 16 != 1:
            hash_input += b'\x00'
        

        h = SHA256.new()
        h.update(hash_input)
        hash = h.digest()

        return b'\x00' + identifier + hash + iv + encrypted


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        # First byte is \x00 => part of auth protocol
        # First byte is anything else => data that the user typed in
        first_byte = message[0]
        if first_byte == 0: # Indexing bytes returns an int
            return True
        return False


    # Processing protocol message
    # (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, secret):
        # Ignore the first byte
        message = message[1:]
        identifier = message[0:6]
        rcvd_hash = message[6:38]
        iv = message[38:54]
        ciphertext = message[54:]

        h = SHA256.new()
        h.update(secret.encode())
        hashed_secret = h.digest()

        timestamp = int(time.time())

        cipher = AES.new(hashed_secret, AES.MODE_CBC, iv=iv)
        decrypted = cipher.decrypt(ciphertext)

        rcvd_timestamp = int.from_bytes(decrypted[0:4], sys.byteorder)
        rcvd_dh_value = int.from_bytes(decrypted[4:], sys.byteorder)

        identifier_bytes = identifier.to_bytes((identifier.bit_length() + 7) // 8)
        timestamp_bytes = rcvd_timestamp.to_bytes((rcvd_timestamp.bit_length() + 7) // 8)
        dh_value_bytes = rcvd_dh_value.to_bytes((rcvd_dh_value.bit_length() + 7) // 8)

        h = SHA256.new()
        h.update(identifier_bytes + timestamp_bytes + dh_value_bytes)
        hash = h.digest()

        # Authenticate sender by checking if decrypted timestamp matches
        print('Authenticating based on clock skew:  received ', rcvd_timestamp, ', expected ', timestamp)
        if abs(rcvd_timestamp - timestamp) > CLOCK_SKEW_S:
            raise SecurityError('Authentication failed :\'(')

        print('Integrity check: received ', rcvd_hash, ', expected ', hash)
        if (rcvd_hash != hash):
            raise SecurityError('Integrity/Authentication is not confirmed due to hash mismatch')

        if self._dh_exp is None:
            # Received initiation for DH exchange. Compute session key and send the next message back.
            self._dh_exp = random.randint(1, P_DH - 1)
            self.SetSessionKey(pow(rcvd_dh_value, self._dh_exp, P_DH))
            return True
        else:
            # Received response to DH initiation. Compute session key.
            self.SetSessionKey(pow(rcvd_dh_value, self._dh_exp, P_DH))
            self._dh_exp = None
            return False


    # Setting the key for the current session
    def SetSessionKey(self, key):
        h = SHA256.new()
        h.update(key.to_bytes(1, sys.byteorder))
        hashed_key = h.digest()
        self._key = hashed_key


    # Encrypting messages
    # : IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        if self._key is None:
            return b'\x01' + plain_text.encode()
        
        iv = get_random_bytes(16)
        cipher = AES.new(self._key, AES.MODE_CBC, iv=iv) # CBC mode needs an iv that is pseudorandom.
        h = SHA256.new()

        text_bytes = plain_text.encode('UTF-8')
        # Need to pad the message before hashing so the hash will match what the receiver sees
        while (sys.getsizeof(text_bytes) + 32) % 16 != 1:
            text_bytes += b'\x00'

        h.update(text_bytes)
        hash_bytes = h.digest()

        mssg_bytes = hash_bytes + text_bytes
        ciph_bytes = cipher.encrypt(mssg_bytes)
        cipher_text = b'\x01' + iv + ciph_bytes

        print (cipher_text) # Temporary print since there is no decrypt yet.
        return cipher_text


    # Decrypting and verifying messages
    # : IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        # Ignore the first byte
        cipher_text = cipher_text[1:]
        if self._key is None:
            return cipher_text.decode()

        iv = cipher_text[0:16]
        ciph_bytes = cipher_text[16:]

        cipher = AES.new(self._key, AES.MODE_CBC, iv=iv)
        h = SHA256.new()

        mssg_bytes = cipher.decrypt(ciph_bytes)
        hash_bytes = mssg_bytes[0:32]
        text_bytes = mssg_bytes[32:]

        h.update(text_bytes)
        print('Integrity check: received ', hash_bytes, ', expected ', h.digest())
        if (hash_bytes != h.digest()):
            raise SecurityError('Integrity/Authentication is not confirmed due to hash mismatch')

        plain_text = text_bytes.decode('UTF-8')
        return plain_text
