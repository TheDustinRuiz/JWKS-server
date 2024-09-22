import time
import uuid

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt

app = Flask(__name__)
rsa_keys = {}
expired_keys = {}


def generate_rsa_key():
    """
    This function generates both a public and private key pair
    with a 1 hour expiration.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    expiry = time.time() + 3600

    rsa_keys[kid] = {
        "private_key": private_key,
        "public_key": public_key,
        "expiry": expiry
    }
    return kid


def get_jwks():
    """
    This function gets unexpired public keys and returns
    them in JWKS format for use in JWT validation
    """
    jwks = {
        "keys": []
    }
    for kid, key_data in rsa_keys.items():
        if time.time() < key_data['expiry']:
            public_key = key_data['public_key']
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            jwks['keys'].append({
                "kid": kid,
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": public_key.public_numbers().n,
                "e": public_key.public_numbers().e
            })
    return jwks


@app.route('/jwks', methods=['GET'])
def jwks():
    """
    This endpoint returns the JWKS for unexpired public keys.
    """
    return jsonify(get_jwks()), 200


@app.route('/auth', methods=['POST'])
def auth():
    """
    This endpoint handles user authentication by generating
    a JWT using a public/private key pair. It allows for the option
    to use expired keys if requested.
    """
    expired = request.args.get('expired', default=False, type=bool)

    if expired and expired_keys:
        kid = list(expired_keys.keys())[0]
        key_data = expired_keys[kid]
    else:
        kid = generate_rsa_key()
        key_data = rsa_keys[kid]

    private_key = key_data['private_key']

    # Create a JWT with the kid in the header
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
        if not expired else int(time.time()) - 3600
    }

    jwt_token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid}
    )

    # Move the key to expired keys storage if expired
    if expired:
        expired_keys[kid] = rsa_keys.pop(kid)

    return jsonify({"token": jwt_token}), 200


@app.before_request
def clean_expired_keys():
    """
    This function removes expired keys from in-memory storage
    by comparing an incoming request's current time with the
    expiry times of the keys.
    """
    now = time.time()
    clean_keys = {kid: key for kid, key in
                  rsa_keys.items() if key['expiry'] > now}
    rsa_keys.clear()
    rsa_keys.update(clean_keys)


@app.route('/', methods=['GET'])
def index():
    """
    This endpoint returns a welcome message for the JWKS server.
    """
    return jsonify({"message": "Welcome to the JWKS Server!"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
