import os
import sys

# Ensure the local A3 folder is on sys.path so we can import main.py
HERE = os.path.dirname(__file__)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from main import AbstractOTSender, AbstractOTReceiver, BloodType

def pretty_bits(n: int, width: int = 3) -> str:
    return "".join(str((n >> i) & 1) for i in reversed(range(width)))

def run_demo():
    print("Oblivious Transfer demo — 1-out-of-8\n")

    sender = AbstractOTSender()
    receiver = AbstractOTReceiver()

    # Receiver chooses a blood type (example: OP)
    choice = BloodType.OP
    print(f"Receiver chooses blood type: {choice.name} (index={int(choice)})")
    print(f"Choice bits: {pretty_bits(int(choice))}\n")

    # Receiver builds an OT request
    public_keys, commitment = receiver.otRequest(choice)
    print("Receiver generated 3 public keys and commitment:")
    print(f" - commitment (sha256 hex): {commitment}")
    print(f" - number of public keys returned: {len(public_keys)}\n")

    # Sender prepares 8 plaintext messages (one per blood type)
    plaintexts = [f"Donor for {bt.name}".encode() for bt in BloodType if bt != BloodType.LAST]
    print("Sender prepared plaintexts (8 messages):")
    for i, pt in enumerate(plaintexts):
        print(f"  [{i}] {pt.decode()}")
    print()

    # Sender processes the request
    ot_data = sender.otSend(plaintexts, public_keys, commitment)
    encrypted_key_pairs, ciphertexts = ot_data
    print("Sender generated encrypted key pairs and ciphertexts:")
    print(f" - number of encrypted key pairs (layers): {len(encrypted_key_pairs)}")
    print(f" - ciphertexts count: {len(ciphertexts)}\n")

    # Receiver recovers the chosen plaintext
    recovered = receiver.otReceive(ot_data)
    print(f"Receiver recovered: {recovered.decode()}\n")

    # Verify recovered matches expected
    expected = plaintexts[int(choice)]
    print("Verification:")
    print(f" - expected message: {expected.decode()}")
    print(f" - recovered equals expected: {recovered == expected}\n")

    # Show that non-chosen plaintexts are not revealed by trying to compare
    print("Sanity: non-chosen plaintexts should not match the recovered value")
    for i, pt in enumerate(plaintexts):
        if i == int(choice):
            continue
        print(f"  index {i}: recovered == plaintext[{i}]? {recovered == pt}")
    print()

    # Demonstrate commitment mismatch handling
    print("Demonstrating commitment mismatch handling (sender should raise an error):")
    fake_commitment = "deadbeef"  # obviously wrong
    try:
        sender.otSend(plaintexts, public_keys, fake_commitment)
    except Exception as e:
        print(f" - sender raised: {type(e).__name__}: {e}")
    else:
        print(" - unexpected: sender did NOT raise on commitment mismatch")


if __name__ == "__main__":
    run_demo()
