import unittest
from main import *

class TestObliviousTransfer(unittest.TestCase):
    
    def test_1_out_of_8(self):
        sender = AbstractOTSender()     # Alice
        receiver = AbstractOTReceiver() # Bob

        # Bob chooses one blood type
        chosen_blood_type = BloodType.ABN

        # Bob creates an OT request for 8 blood types
        (public_keys, commitment) = receiver.otRequest(chosen_blood_type)

        # Alice prepares 8 plaintexts (one for each blood type)
        plaintexts = [b"BloodTypeA", b"BloodTypeB", b"BloodTypeAB", b"BloodTypeO",
                      b"BloodTypeA+", b"BloodTypeB+", b"BloodTypeAB+", b"BloodTypeO+"]

        # Alice sends encrypted messages
        (encrypted_keys, ciphertexts) = sender.otSend(plaintexts, public_keys, commitment)

        # Bob receives and decrypts his chosen message
        received_plaintext = receiver.otReceive(encrypted_keys, ciphertexts)

        # Verify that Bob received the correct plaintext
        self.assertEqual(received_plaintext, plaintexts[chosen_blood_type])
        
    def test_invalid_commitment(self):
        sender = AbstractOTSender()     # Alice
        receiver = AbstractOTReceiver() # Bob

        # Bob chooses one blood type
        chosen_blood_type = BloodType.ABN

        # Bob creates an OT request for 8 blood types
        (public_keys, commitment) = receiver.otRequest(chosen_blood_type)

        # Alice prepares 8 plaintexts (one for each blood type)
        plaintexts = [b"BloodTypeA", b"BloodTypeB", b"BloodTypeAB", b"BloodTypeO",
                      b"BloodTypeA+", b"BloodTypeB+", b"BloodTypeAB+", b"BloodTypeO+"]

        # Tamper with the commitment to simulate an invalid case
        invalid_commitment = os.urandom(len(commitment))

        # Alice attempts to send encrypted messages with invalid commitment
        with self.assertRaises(ValueError) as context:
            sender.otSend(plaintexts, public_keys, invalid_commitment)
        
        self.assertIn("Commitment does not match provided public keys", str(context.exception))
    
    def test_incorrect_number_of_plaintexts(self):
        sender = AbstractOTSender()     # Alice
        receiver = AbstractOTReceiver() # Bob

        # Bob chooses one blood type
        chosen_blood_type = BloodType.ABN

        # Bob creates an OT request for 8 blood types
        (public_keys, commitment) = receiver.otRequest(chosen_blood_type)

        # Alice prepares incorrect number of plaintexts (only 7 instead of 8)
        plaintexts = [b"BloodTypeA", b"BloodTypeB", b"BloodTypeAB", b"BloodTypeO",
                      b"BloodTypeA+", b"BloodTypeB+", b"BloodTypeAB+"]

        # Alice attempts to send encrypted messages with incorrect number of plaintexts
        with self.assertRaises(ValueError) as context:
            sender.otSend(plaintexts, public_keys, commitment)
        
        self.assertIn("Number of plaintexts must match number of blood types", str(context.exception))
    
    def test_incorrect_number_of_public_keys(self):
        sender = AbstractOTSender()     # Alice
        receiver = AbstractOTReceiver() # Bob

        # Bob chooses one blood type
        chosen_blood_type = BloodType.ABN

        # Bob creates an OT request for 8 blood types
        (public_keys, commitment) = receiver.otRequest(chosen_blood_type)

        # Modify public keys to have incorrect number (only 2 instead of 3)
        invalid_public_keys = public_keys[:2]

        # Alice prepares 8 plaintexts (one for each blood type)
        plaintexts = [b"BloodTypeA", b"BloodTypeB", b"BloodTypeAB", b"BloodTypeO",
                      b"BloodTypeA+", b"BloodTypeB+", b"BloodTypeAB+", b"BloodTypeO+"]

        # Alice attempts to send encrypted messages with incorrect number of public keys
        with self.assertRaises(ValueError) as context:
            sender.otSend(plaintexts, invalid_public_keys, commitment)
        
        self.assertIn("Number of public keys must be 3 for 3 layers", str(context.exception))
    
    def test_fake_public_key(self):
        sender = AbstractOTSender()     # Alice
        receiver = AbstractOTReceiver() # Bob

        # Bob chooses one blood type
        chosen_blood_type = BloodType.ABN

        # Bob creates an OT request for 8 blood types
        (public_keys, commitment) = receiver.otRequest(chosen_blood_type)

        # Modify one public key to be invalid
        fake_public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        invalid_public_keys = [public_keys[0], fake_public_key, public_keys[2]]

        # Alice prepares 8 plaintexts (one for each blood type)
        plaintexts = [b"BloodTypeA", b"BloodTypeB", b"BloodTypeAB", b"BloodTypeO",
                      b"BloodTypeA+", b"BloodTypeB+", b"BloodTypeAB+", b"BloodTypeO+"]

        # Alice attempts to send encrypted messages with a fake public key
        with self.assertRaises(Exception) as context:
            sender.otSend(plaintexts, invalid_public_keys, commitment)
        
        self.assertIn("encryption/decryption failed", str(context.exception).lower())
    
if __name__ == "__main__":
    unittest.main()