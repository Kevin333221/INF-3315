# Assignment 3 - 1-Out-of-8 Oblivious Transfer for Secure Blood Donor Matching.

# Assignement text

Consider the scenario of a hospital service that needs to find donors with a specific blood type.
A 3rd party donor service maintains an internal database of donor names and blood types.
The donor service discloses the name of a single donor matching a requested blood type.

Let's assume the health authorities have the following two requirements:

1. For each request, the hospital should not learn the names of donors with non-matching blood types.
2. The donor service should not learn about what blood type is being requested.

There are 8 different blood types: _A-_, _A+_, _B-_, _B+_, _O-_, _O+_, _AB-_, _AB+_.

# Oblivious Transfer Protocol

My python library supports a privacy-preserving blood donor service that is based on oblivious transfer. Here is the following API:

- `Class BloodType`
- `Class AbstractOTReceiver`
  - `Func otRequest(Bloodtype)`
  - `Func otReceive(data)`
- `Class AbstractOTSender`
  - `Func otSend(plaintext, request)`
