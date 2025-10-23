import unittest
from main import *

class TestObliviousTransfer(unittest.TestCase):
    
    def test_ot_protocol(self):
        # Initialize sender and receiver
        sender = AbstractOTSender()
        receiver = AbstractOTReceiver()

        # Sample plaintexts for each blood type
        plaintexts = [
            f"Message for blood type {bt.name}".encode()
            for bt in BloodType if bt != BloodType.LAST
        ]
        
        # Receiver chooses a blood type
        chosen_blood_type = BloodType.AN
        public_keys, commitment = receiver.otRequest(chosen_blood_type)
        
        # Sender processes the OT request and generates ciphertexts
        data = sender.otSend(plaintexts, public_keys, commitment)
        
        # Receiver decrypts the chosen ciphertext
        decrypted_plaintext = receiver.otReceive(data)

        # Verify that the decrypted plaintext matches the expected one
        self.assertEqual(decrypted_plaintext, plaintexts[chosen_blood_type])

    def test_invalid_blood_type(self):
        sender = AbstractOTSender()
        receiver = AbstractOTReceiver()

        plaintexts = [
            f"Message for blood type {bt.name}".encode()
            for bt in BloodType if bt != BloodType.LAST
        ]
        
        # Use an invalid blood type
        invalid_blood_type = BloodType.LAST
        with self.assertRaises(IndexError):
            receiver.otRequest(invalid_blood_type)

    def test_commitment_mismatch(self):
        sender = AbstractOTSender()
        receiver = AbstractOTReceiver()

        plaintexts = [
            f"Message for blood type {bt.name}".encode()
            for bt in BloodType if bt != BloodType.LAST
        ]
        
        chosen_blood_type = BloodType.BP
        public_keys, commitment = receiver.otRequest(chosen_blood_type)
        
        # Tamper with the commitment
        fake_commitment = b"fake_commitment"
        
        with self.assertRaises(ValueError):
            sender.otSend(plaintexts, public_keys, fake_commitment)

    def test_incorrect_number_of_plaintexts(self):
        sender = AbstractOTSender()
        receiver = AbstractOTReceiver()

        # Provide incorrect number of plaintexts
        plaintexts = [
            f"Message for blood type {bt.name}".encode()
            for bt in BloodType if bt != BloodType.LAST
        ][:-1]  # Remove one to make it incorrect
        
        chosen_blood_type = BloodType.OP
        public_keys, commitment = receiver.otRequest(chosen_blood_type)
        
        with self.assertRaises(ValueError):
            sender.otSend(plaintexts, public_keys, commitment)

    def test_incorrect_number_of_public_keys(self):
        sender = AbstractOTSender()
        receiver = AbstractOTReceiver()

        plaintexts = [
            f"Message for blood type {bt.name}".encode()
            for bt in BloodType if bt != BloodType.LAST
        ]
        
        chosen_blood_type = BloodType.ABP
        public_keys, commitment = receiver.otRequest(chosen_blood_type)
        
        # Remove one public key to make it incorrect
        public_keys = public_keys[:-1]
        
        with self.assertRaises(ValueError):
            sender.otSend(plaintexts, public_keys, commitment)

    def test_non_chosen_plaintext_not_leaked(self):
        sender = AbstractOTSender()
        receiver = AbstractOTReceiver()

        plaintexts = [
            f"Message for blood type {bt.name}".encode()
            for bt in BloodType if bt != BloodType.LAST
        ]
        
        chosen_blood_type = BloodType.BN
        public_keys, commitment = receiver.otRequest(chosen_blood_type)
        
        data = sender.otSend(plaintexts, public_keys, commitment)
        
        decrypted_plaintext = receiver.otReceive(data)

        # Ensure only the chosen plaintext is revealed
        for i, pt in enumerate(plaintexts):
            if i == chosen_blood_type:
                self.assertEqual(decrypted_plaintext, pt)
            else:
                self.assertNotEqual(decrypted_plaintext, pt)

if __name__ == "__main__":
    unittest.main()