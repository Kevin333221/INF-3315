# INF-3315 Project

This repository contains the project files for Assignment 2 of the INF-3315 course at UiT.

## Table of Contents

- [About](#about)
- [Requirements](#requirements)
- [Usage](#usage)

## About

This project implements a simplified secure voting protocol using Shamir’s Secret Sharing (SSS) principles.
Each voter’s vote is hidden in a random polynomial, and shares of that polynomial are distributed to multiple authorities.
The authorities can later reconstruct the total sum of votes without ever learning any individual voter’s choice.

This implementation demonstrates how polynomial secret sharing can be used to ensure vote privacy and integrity in a distributed setting. Each voter encodes their vote (0 or 1) as the constant term of a random polynomial. The polynomial is evaluated at several public authority keys to produce shares. Authorities collect and sum the shares to compute the total vote count using Lagrange interpolation over a finite field. No individual authority or subset of authorities can learn a specific voter’s choice, as long as not all authorities collude.

## Requirements

- (Might need a conda environment since i only got it to work with conda)
- Galois

## Usage

To run my program, change the variables in the `ìf __name__ == "__main__"` block such as:

- n_voters : The number of participants
- k_authorities : The number of authorities
- prime : The prime number of the field
