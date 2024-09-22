#JWKS-server

RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

NOTE: No Test Suite or Test Coverage is present since the skeleton for this project was not requested.

Tasks:
- [x] Key Generation
     - [x] Implement RSA key pair generation.
     - [x] Associate a Key ID (kid) and expiry timestamp with each key.
- [x] Web server with two handlers
     - [x] Serve HTTP on port 8080
     - [x] A RESTful JWKS endpoint that serves the public keys in JWKS format. Only serve keys that have not expired.
     - [x] A /auth endpoint that returns an unexpired, signed JWT on a POST request. If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry.