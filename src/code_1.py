import galois

class VotingProtocol:
    def __init__(self, n_voters: int, k_authorities: int, prime: int = 19):
        self.n = n_voters
        self.k = k_authorities
        self.prime = prime
        self.GF = galois.GF(prime)
        
        assert self.k <= self.n, "Number of authorities must be less than or equal to number of voters"
        
        self.authorities = [i for i in range(1, self.k + 1)]  # public keys (xk)

    def generate_polynomial(self, vote: int) -> galois.Poly:
        """
        Generate a polynomial p_n(x) of degree (k-1) with constant term = vote
        """
        coeffs = [self.GF.Random() for _ in range(self.k - 1)] + [vote]
        
        return galois.Poly(coeffs, field=self.GF)

    def cast_vote(self, voter_id: int, vote: int) -> list[dict]:
        """
        Voter encodes their vote and generates shares for each authority.
        """
        poly = self.generate_polynomial(vote)
        shares = []
        for xk in self.authorities:
            shares.append({
                "voter_id": voter_id,
                "authority_id": xk,
                "share": int(poly(xk))
            })
        return shares

    def tally_votes(self, all_votes) -> int:
        """
        Authorities collect shares and reconstruct final polynomial P(x).
        The constant term of P(x) is the total number of votes.
        """
        # Group shares by authority_id
        # Initialize a dictionary to store the sum of shares for each authority
        sums = {}

        # Iterate over each authority's public key
        for authority_id in self.authorities:
            shares_for_authority = []
            
            # Iterate over all votes to find shares for the current authority
            for votes in all_votes:
                for vote in votes:
                    if vote["authority_id"] == authority_id:
                        shares_for_authority.append(vote["share"])

            # Compute the sum of shares
            sums[authority_id] = sum(shares_for_authority) % self.GF.order
            
        # Use Lagrange interpolation to reconstruct polynomial P(x)
        x_vals, y_vals = zip(*sums.items())    
        P = galois.lagrange_poly(self.GF(x_vals), self.GF(y_vals))
        return int(P.coefficients()[-1])

if __name__ == "__main__":

    ###########################################################################
    # Change these parameters to test different scenarios
    ###########################################################################

    n_voters = 5            # Total number of voters
    k_authorities = 3       # Number of authorities needed to reconstruct the vote
    prime = 2**127 - 1      # The 11th Mersenne prime

    ###########################################################################
    # Example usage of the VotingProtocol
    ###########################################################################

    protocol = VotingProtocol(n_voters, k_authorities, prime=prime)

    # A vote is either 0 or 1
    votes = [1, 0, 1, 1, 0]  # Example votes from 5 voters
    
    all_votes = [protocol.cast_vote(voter_id, vote) for voter_id, vote in enumerate(votes)]
    
    total_votes = protocol.tally_votes(all_votes)
    print(f"\nFinal tally (sum of votes) = {total_votes}")
