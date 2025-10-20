import unittest
from main import AbstractOTReceiver, AbstractOTSender, BloodType

class TestObliviousTransfer(unittest.TestCase):
    
    def test_1_of_out_8_OT_protocol(self):
        receiver = AbstractOTReceiver()
        sender = AbstractOTSender()
        
        # Receiver chooses a blood type
        choice = BloodType.OP
        
        # Receiver creates OT request
        public_keys, commitment = receiver.otRequest(choice)
        
        # Sender prepares messages for each blood type
        messages = [b"Data for AN", b"Data for AP", b"Data for BN", b"Data for BP",
                    b"Data for ON", b"Data for OP", b"Data for ABP", b"Data for ABN"]
        
        # Sender processes OT request and encrypts messages
        ciphertexts = sender.otSend(messages, public_keys, commitment)

        # Receiver receives and decrypts the chosen message
        received_message = receiver.otReceive(ciphertexts)
        
        # Verify that the received message matches the chosen blood type's data
        self.assertEqual(received_message, messages[choice])
            
    def test_encryption_decryption_failure(self):
        receiver = AbstractOTReceiver()
        sender = AbstractOTSender()
        
        # Receiver chooses a blood type
        choice = BloodType.AN
        
        # Receiver creates OT request
        public_keys, commitment = receiver.otRequest(choice)
        
        # Sender prepares messages
        messages = [b"Data for AN", b"Data for AP", b"Data for BN", b"Data for BP",
                    b"Data for ON", b"Data for OP", b"Data for ABP", b"Data for ABN"]
        
        # Corrupt one of the public keys to simulate encryption failure
        public_keys[3] = None  # Invalid public key
        
        with self.assertRaises(ValueError):
            sender.otSend(messages, public_keys, commitment)

    def test_decryption_failure(self):
        receiver = AbstractOTReceiver()
        sender = AbstractOTSender()
        
        # Receiver chooses a blood type
        choice = BloodType.BN
        
        # Receiver creates OT request
        public_keys, commitment = receiver.otRequest(choice)
        
        # Sender prepares messages
        messages = [b"Data for AN", b"Data for AP", b"Data for BN", b"Data for BP",
                    b"Data for ON", b"Data for OP", b"Data for ABP", b"Data for ABN"]
        
        # Sender processes OT request and encrypts messages
        ciphertexts = sender.otSend(messages, public_keys, commitment)
        
        # Corrupt one of the ciphertexts to simulate decryption failure
        ciphertexts[choice] = b"corrupted data"
        
        with self.assertRaises(ValueError):
            receiver.otReceive(ciphertexts)
            
    def test_commitment_mismatch(self):
        receiver = AbstractOTReceiver()
        sender = AbstractOTSender()
        
        # Receiver chooses a blood type
        choice = BloodType.AP
        
        # Receiver creates OT request
        public_keys, _ = receiver.otRequest(choice)

        # Sender prepares messages
        messages = [b"Data for AN", b"Data for AP", b"Data for BN", b"Data for BP",
                    b"Data for ON", b"Data for OP", b"Data for ABP", b"Data for ABN"]
        
        # Modify the commitment to simulate a mismatch
        bad_commitment = "invalid_commitment_hash"
        
        with self.assertRaises(ValueError):
            sender.otSend(messages, public_keys, bad_commitment)
         
    def test_invalid_choice(self):
        receiver = AbstractOTReceiver()
        
        # Receiver chooses an invalid blood type index
        invalid_choice = 10  # Out of range
        
        with self.assertRaises(IndexError):
            receiver.otRequest(invalid_choice)
            
    def test_non_enum_choice(self):
        receiver = AbstractOTReceiver()
        
        # Receiver chooses a non-enum value
        non_enum_choice = "AP"  # Should be BloodType.AP
        
        with self.assertRaises(ValueError):
            receiver.otRequest(non_enum_choice)
    
if __name__ == "__main__":
    unittest.main()