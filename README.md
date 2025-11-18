# Secure videochat app
## Team
- James C. Underwood
- Ahmed M. Al Sunbati


## Key exchange flow
### Initiator POV
Once the initiator gets the `HELLO_ACK` function they:
1. Generate the parameters with `generate_dh_parameters`.
2. Serialize the parameters with `serialize_parameters` and send to the listener these bytes in a type `4` message (`KEY_EXCHANGE_PARAMETERS`) to the listener.
3. Generate public keys and send a type 5 message (`KEY_EXCHANGE_PUBLIC`) to the listener.
4. Block in a loop until we get a `KEY_EXCHANGE_PUBLIC` message from the listener.
5. Calculate the shared secret and get the derived key.

### Listener POV
1. After sending `HELLO_ACK`, block till we receive a `4` message (`KEY_EXCHANGE_PARAMETERS`).
2. Generate public keys and send a type 5 message (`KEY_EXCHANGE_PUBLIC`) to the initiator.
3. Block in a loop until we get a `KEY_EXCHANGE_PUBLIC` message from the listener.
4. Calculate shared secret and get the derived key.