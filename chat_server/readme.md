 ```sh
 openssl genpkey -algorithm ed25519 -out fixtures/encoding.pem
 openssl pkey -in fixtures/encoding.pem -pubout -out fixtures/decoding.pem

#online jwt decoder
 jwt.io
 ```
