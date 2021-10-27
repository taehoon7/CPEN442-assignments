from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self._messages_used = 0 # I think we said we would ask the user to make a new session key after a vertain number of time/messages, maybe nag them about this if that happens
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        return ""


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # : IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        iv = get_random_bytes(16)
        cipher = AES.new(self._key, AES.MODE_CBC, iv=iv) # CBC mode needs an iv that is pseudorandom.
        h = SHA256.new()

        text_bytes = plain_text.encode('UTF-8')

        h.update(text_bytes)
        hash_bytes = h.digest()

        mssg_bytes = hash_bytes + text_bytes
        ciph_bytes = cipher.encrypt(mssg_bytes)
        cipher_text = iv + ciph_bytes

        self._messages_used += 1
        # if (self._messages_used > message threshold || initial auth message time - current time > time threshold) remind user to make a new session TODO

        print (cipher_text) # Temporary print since there is no decrypt yet.
        return cipher_text


    # Decrypting and verifying messages
    # : IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        iv = cipher_text[0:16]
        ciph_bytes = cipher_text[16:]

        cipher = AES.new(self._key, AES.MODE_CBC, iv=iv)
        h = SHA256.new()

        mssg_bytes = AES.decrypt(ciph_bytes)
        hash_bytes = mssg_bytes[0:64]
        text_bytes = mssg_bytes[64:]

        h.update(text_bytes)
        if (hash_bytes != h.digest())
            return 'Integrity is not confirmed, due to hash mismatch'

        self._messages_used += 1
        # if (self._messages_used > message threshold || initial auth message time - current time > time threshold) remind user to make a new session TODO

        plain_text = text_bytes.decode('UTF-8')
        return plain_text
