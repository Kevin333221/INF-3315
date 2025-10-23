import hashlib
import math
from enum import IntEnum
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Padding scheme for RSA encryption/decryption
def Padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

# Utility function to XOR two byte strings
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings and return the result.

    Notes:
    - This function uses zip so the result length equals the shorter input.
      In this project both operands are fixed-length symmetric keys so this
      is fine. If you use variable-length inputs, ensure the lengths match
      before calling.

    Args:
        a: first byte string
        b: second byte string

    Returns:
        bytes: XOR of the two inputs (length = min(len(a), len(b))).
    """
    return bytes(x ^ y for x, y in zip(a, b))

# Function to create a commitment from public keys
def create_commitment(public_keys: list[rsa.RSAPublicKey]) -> str:
    """
    Create a SHA-256 commitment (hex string) over a list of public keys.

    The commitment serializes each public key (DER SubjectPublicKeyInfo when
    possible) and hashes the concatenation. The commitment lets the sender
    verify the receiver did not change the public keys after the request.

    Args:
        public_keys: iterable of RSA public key objects (or objects convertible
                     to bytes via str()).

    Returns:
        str: hex-encoded SHA-256 digest of the concatenated public key bytes.
    """
    pk_bytes = b""
    for pk in public_keys:
        pk: rsa.RSAPublicKey
        if hasattr(pk, 'public_bytes'):
            pk_bytes += pk.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            pk_bytes += str(pk).encode()

    commitment = hashlib.sha256(pk_bytes).hexdigest()
    return commitment

class BloodType(IntEnum):
    AN = 0; AP = 1; BN = 2; BP = 3; ON = 4; OP = 5; ABP = 6; ABN = 7
    LAST = 8  # Number of entries

class AbstractOTReceiver:
    def __init__(self):
        # List of RSA private keys (one per layer). These must be kept secret.
        self.private_keys: list[rsa.RSAPrivateKey] = []

    def otRequest(self, c: BloodType) -> tuple[list[rsa.RSAPublicKey], str]:

        if not isinstance(c, int):
            raise ValueError("Chosen index must be an integer")

        if c < 0 or c >= BloodType.LAST:
            raise IndexError("Chosen index out of range")

        # Compute choice bits for the OT protocol (b2, b1, b0)
        self.choice_bits = [(c >> i) & 1 for i in reversed(range(3))]

        # Generate 3 public/private key pairs (one per layer)
        requests = []
        for _ in range(3):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            self.private_keys.append(private_key)
            requests.append(public_key)

        # Create a commitment to the public keys
        commitment = create_commitment(requests)
        return requests, commitment

    def otReceive(self, data: list[bytes]) -> bytes:

        enc_pairs, ciphertexts = data

        # Recover one symmetric key per layer by decrypting the chosen entry
        keys = []
        for i in range(3):
            enc_pair = enc_pairs[i]
            chosen_key = enc_pair[self.choice_bits[i]]
            key_bytes = self.private_keys[i].decrypt(chosen_key, Padding())
            keys.append(key_bytes)

        # Combine the three keys (XOR) to form the final symmetric key
        final_key = xor_bytes(xor_bytes(keys[0], keys[1]), keys[2])

        # Compute the index into the ciphertext list using bits b2,b1,b0
        index = (self.choice_bits[0] << 2) | (self.choice_bits[1] << 1) | (self.choice_bits[2] << 0)
        plaintext = xor_bytes(ciphertexts[index], final_key)
        return plaintext
        
class AbstractOTSender:

    def otSend(self, plaintexts, public_keys, commitment: str) -> list[bytes]:

        # Verify commitment
        if create_commitment(public_keys) != commitment:
            raise ValueError("Commitment does not match provided public keys")

        if len(plaintexts) != BloodType.LAST:
            raise ValueError("Number of plaintexts must match number of blood types")

        if len(public_keys) != 3:
            raise ValueError("Number of public keys must be 3 for 3 layers")

        # Generate 3 levels of random symmetric keys (two choices per layer)
        layer_keys = [[os.urandom(32), os.urandom(32)] for _ in range(3)]

        # Encrypt keys under the receiver's public keys so the receiver can
        # decrypt exactly one key per layer.
        encrypted_keys = []
        for i in range(3):
            pk: rsa.RSAPublicKey = public_keys[i]
            enc_k0 = pk.encrypt(layer_keys[i][0], Padding())
            enc_k1 = pk.encrypt(layer_keys[i][1], Padding())
            encrypted_keys.append((enc_k0, enc_k1))

        # Build ciphertexts: for each message pick the three keys according to
        # the message index bits and XOR them together with the plaintext.
        ciphertexts = []
        for i in range(BloodType.LAST):
            bits = [(i >> j) & 1 for j in reversed(range(3))]
            layer1_key = layer_keys[0][bits[0]]
            layer2_key = layer_keys[1][bits[1]]
            layer3_key = layer_keys[2][bits[2]]
            key_combo = xor_bytes(xor_bytes(layer1_key, layer2_key), layer3_key)
            ciphertexts.append(xor_bytes(plaintexts[i], key_combo))

        return (encrypted_keys, ciphertexts)

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
