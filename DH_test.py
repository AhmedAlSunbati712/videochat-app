from DH import *

alice_parameters = generate_dh_parameters(generator=2, key_size=2048)
bob_parameters = deserialize_parameters_bytes(serialize_parameters(alice_parameters))

alice_public_key, alice_private_key = generate_dh_keys(parameters=alice_parameters)

bob_public_key, bob_private_key = generate_dh_keys(parameters=bob_parameters)

alice_public_key_serialized = serialize_public_key(alice_public_key)
bob_public_key_serialized = serialize_public_key(bob_public_key)

# Now bob desrializes alice public key
alice_public_key_dserialized = deserialize_public_key_bytes(alice_public_key_serialized)

# Alice desrializes bob public key
bob_public_key_dserialized = deserialize_public_key_bytes(bob_public_key_serialized)

# bob calculates shared secret
bob_shared_secret = calculate_shared_secret(bob_private_key, alice_public_key_dserialized)

# alice calculates shared secret
alice_shared_secret = calculate_shared_secret(alice_private_key, bob_public_key_dserialized)

# derived key for alice and bob
bob_derived_key = get_derived_key(bob_shared_secret)
alice_derived_key = get_derived_key(alice_shared_secret)

#alice sends message to bob
message = "Hello from alice"
message_bytes = message.encode('utf-8') # Convert string to bytes

# Use the DERIVED key
encrypted_message = encrypt(alice_derived_key, message_bytes) 

decrypted_message_bytes = decrypt(bob_derived_key, encrypted_message)

# Convert bytes back to string
print("Bob: Alice says: " + decrypted_message_bytes.decode('utf-8'))