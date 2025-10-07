import unittest
import random

from code_1 import VotingProtocol

class TestVotingProtocol(unittest.TestCase):

    def setUp(self):
        self.protocol = VotingProtocol(n_voters=20, k_authorities=5, prime=104729)

    def test_all_no_votes(self):
        votes = [0] * 20  # All voters say no
        all_votes = [self.protocol.cast_vote(voter_id, vote) for voter_id, vote in enumerate(votes)]
        
        print(all_votes)  # Debugging output to inspect shares
                
        total_votes = self.protocol.tally_votes(all_votes)
        self.assertEqual(total_votes, sum(votes))  # Should be 0

    def test_all_yes_votes(self):
        votes = [1] * 20  # All voters say yes
        all_votes = [self.protocol.cast_vote(voter_id, vote) for voter_id, vote in enumerate(votes)]
        total_votes = self.protocol.tally_votes(all_votes)
        self.assertEqual(total_votes, sum(votes))  # Should be 20

    def test_random_votes(self):
        random.seed(42)  # Set seed for reproducibility
        votes = [random.randint(0, 1) for _ in range(20)]  # Random yes or no votes
        all_votes = [self.protocol.cast_vote(voter_id, vote) for voter_id, vote in enumerate(votes)]
        total_votes = self.protocol.tally_votes(all_votes)
        self.assertEqual(total_votes, sum(votes))  # Should match the sum of random votes

if __name__ == "__main__":
    print("Running unit tests...")
    unittest.main()
