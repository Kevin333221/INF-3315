import hashlib
from enum import IntEnum
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class BloodType(IntEnum):
    AN = 0; AP = 1; BN = 2; BP = 3; ON = 4; OP = 5; ABP = 6; ABN = 7
    LAST = 8  # Number of entries

class AbstractOTReceiver:
    
    def otRequest(self, c: BloodType) -> tuple[list[rsa.RSAPublicKey], str]:
        """
        Creates OT request data for chosen blood type index (c).
        Returns a list of public keys where only one has a matching private key.
        """

        if not isinstance(c, int):
            raise ValueError("Chosen index must be an integer")

        if c < 0 or c >= BloodType.LAST:
            raise IndexError("Chosen index out of range")
        
        # Generate key pairs for all blood types
        self.private_keys = [None] * BloodType.LAST
        self.public_keys = []
        self.chosen_index = c

        for i in range(BloodType.LAST):
            
            # Generate a new RSA key pair
            temp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pk = temp_key.public_key()

            if i == c:
                self.private_keys[i] = temp_key # Store private key only for chosen index
            else:
                del temp_key                    # Delete private key if not chosen (simulate unlinkability) 

            self.public_keys.append(pk)

        # Commitment: hash of all serialized public keys (prevents later change)
        commitment = create_commitment(self.public_keys)

        return self.public_keys, commitment

    def otReceive(self, data: list[bytes]) -> bytes:
        """
        Given the sender's ciphertexts, decrypt only the one that matches
        the receiver's chosen private key.
        """

        chosen_private_key: rsa.RSAPrivateKey = self.private_keys[self.chosen_index]
        ciphertext = data[self.chosen_index]

        # Decrypt the chosen ciphertext
        plaintext = chosen_private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return plaintext

class AbstractOTSender:

    def otSend(self, plaintexts: list[bytes], public_keys: list[rsa.RSAPublicKey], commitment: str) -> list[bytes]:
        """
        Encrypts each plaintext with the corresponding public key.
        Returns a list of ciphertexts (one per message).
        """

        # Verify commitment matches the provided public keys
        computed_commitment = create_commitment(public_keys)
        if computed_commitment != commitment:
            raise ValueError("Commitment does not match public keys")

        ciphertexts = []
        # for plaintext, public_key in zip(plaintexts, public_keys):
        #     if public_key is None:
        #         raise ValueError("Invalid public key")
        #     try:
        #         # Encrypt the message with the corresponding public key
        #         ciphertext = public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        #         ciphertexts.append(ciphertext)
        #     except Exception:
        #         raise ValueError("Encryption failed for one of the messages.")
            
        return ciphertexts

def create_commitment(public_keys: list[rsa.RSAPublicKey]) -> str:
    pk_bytes = b""
    for pk in public_keys:
        pk: rsa.RSAPublicKey
        if hasattr(pk, 'public_bytes'):
            pk_bytes += pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            pk_bytes += str(pk).encode()
                
    commitment = hashlib.sha256(pk_bytes).hexdigest()
    return commitment

if __name__ == "__main__":
    sender = AbstractOTSender()     # Alice
    receiver = AbstractOTReceiver() # Bob

    # Bob chooses one blood type
    chosen_blood_type = BloodType.ABN

    # Bob creates an OT request for 8 blood types
    public_keys, commitment = receiver.otRequest(chosen_blood_type)

    # Alice prepares 8 plaintext messages
    plaintexts = [
        f"Message for blood type {bt.name}".encode()
        for bt in BloodType if bt != BloodType.LAST
    ]

    # Alice encrypts them all
    ot_data = sender.otSend(plaintexts, public_keys, commitment)

    # Bob receives his chosen message
    received_message = receiver.otReceive(ot_data)
    print(f"Bob received message: {received_message.decode()}")
