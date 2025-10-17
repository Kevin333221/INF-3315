from enum import IntEnum

class BloodType(IntEnum):
    AN = 0; AP = 1; BN = 3; BP = 3; ON = 4; OP = 5; ABP = 6; ABN = 7
    LAST = 8; # Number of entries
    
class AbstractOTReceiver:
    
    # Create OT request data for the chosen blood type
    def otRequest(self, c: BloodType):
        """
        Prepare the receiver's message to send to the sender.
        Input: c - the chose blood type index (0-7)
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
    def otSend(self, pt, req):
        """
        Use the receiver's request to prepare the OT response that allows the receiver to learn only the plaintext.
        """
        pass