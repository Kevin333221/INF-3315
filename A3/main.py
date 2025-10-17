from enum import IntEnum
from cryptography.hazmat.primitives.asymmetric import rsa
class BloodType(IntEnum):
    AN = 0; AP = 1; BN = 2; BP = 3; ON = 4; OP = 5; ABP = 6; ABN = 7
    LAST = 8; # Number of entries
    
class AbstractOTReceiver:
    
    def init(self):
        """
        The Receiver generates a public-private key pair using cryptography tools such as RSA. 
        Noted as (pk, sk), it generates a random public key rk, 
        but the receiver does not own the corresponding private key.
        """
        
        self.public_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        ).public_key()

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )


    # Create OT request data for the chosen blood type
    def otRequest(self, c: BloodType):
        """
        Prepare the receiver's message to send to the sender.
        Input: c - the chosen blood type index (0-7)
        Output: Request data that does not reveal c.
        """
        pass
    
    # Return plaintext message from the sender's data
    def otReceiver(self, data) -> bytes:
        """
        Process the sender's reply and return the plaintext message corresponding to the chosen blood type.
        """
        return bytes(0)
    
class AbstractOTSender:
    
    # Generate an OT message from the plaintext and receiver's request
    def otSend(self, plaintext, request):
        """
        Use the receiver's request to prepare the OT response that allows the receiver to learn only the plaintext.
        """
        pass
    
if __name__ == "__main__":
    # Example usage
    receiver = AbstractOTReceiver()
    sender = AbstractOTSender()
    
    private_messages = [
        b"Message for AN", b"Message for AP", b"Message for BN", b"Message for BP",
        b"Message for ON", b"Message for OP", b"Message for ABP", b"Message for ABN"
    ]
    
    chosen_blood_type = BloodType.ON
    request = receiver.otRequest(chosen_blood_type)
    response = sender.otSend(private_messages, request)
    message = receiver.otReceiver(response)
    print(f"Received message: {message.decode()}")
    