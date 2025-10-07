import unittest
from code_1 import VotingProtocol

class TestVotingProtocol(unittest.TestCase):

    def setUp(self):
        self.protocol = VotingProtocol(n_voters=5, k_authorities=3, prime=104729)

    def test_vote_casting(self):
        shares = self.protocol.cast_vote(voter_id=1, vote=1)
        self.assertEqual(len(shares), 3)
        self.assertEqual(shares[0]["voter_id"], 1)
        
        self.assertIn(shares[0]["authority_id"], self.protocol.authorities)
        self.assertIn(shares[1]["authority_id"], self.protocol.authorities)
        self.assertIn(shares[2]["authority_id"], self.protocol.authorities)
        

    def test_tally_votes(self):
        votes = [1, 0, 1, 1, 0]
        all_votes = [self.protocol.cast_vote(voter_id, vote) for voter_id, vote in enumerate(votes)]
        total_votes = self.protocol.tally_votes(all_votes)
        self.assertEqual(total_votes, sum(votes))

if __name__ == "__main__":
    print("Running unit tests...")
    unittest.main()
