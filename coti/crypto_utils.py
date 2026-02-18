from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from eth_keys import keys
from .types import CtUint256, ItUint256, CtString, CtUint, ItString, ItUint

block_size = AES.block_size
address_size = 20
function_selector_size = 4
ct_size = 32
key_size = 32


def encrypt(user_aes_key: bytes, plaintext: int):
    # Ensure plaintext is smaller than 128 bits (16 bytes)
    if len(plaintext) > block_size:
        raise ValueError("Plaintext size must be 128 bits or smaller.")

    # Ensure key size is 128 bits (16 bytes)
    if len(user_aes_key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(user_aes_key, AES.MODE_ECB)

    # Generate a random value 'r' of the same length as the block size
    r = get_random_bytes(block_size)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # Pad the plaintext with zeros if it's smaller than the block size
    plaintext_padded = bytes(block_size - len(plaintext)) + plaintext

    # XOR the encrypted random value 'r' with the plaintext to obtain the ciphertext
    ciphertext = bytes(x ^ y for x, y in zip(encrypted_r, plaintext_padded))

    return ciphertext, r


def decrypt(user_aes_key: bytes, r: bytes, ciphertext: bytes):
    if len(ciphertext) != block_size:
        raise ValueError("Ciphertext size must be 128 bits.")

    # Ensure key size is 128 bits (16 bytes)
    if len(user_aes_key) != block_size:
        raise ValueError("Key size must be 128 bits.")

    # Ensure random size is 128 bits (16 bytes)
    if len(r) != block_size:
        raise ValueError("Random size must be 128 bits.")

    # Create a new AES cipher block using the provided key
    cipher = AES.new(user_aes_key, AES.MODE_ECB)

    # Encrypt the random value 'r' using AES in ECB mode
    encrypted_r = cipher.encrypt(r)

    # XOR the encrypted random value 'r' with the ciphertext to obtain the plaintext
    plaintext = bytes(x ^ y for x, y in zip(encrypted_r, ciphertext))

    return plaintext


def generate_aes_key():
    # Generate a random 128-bit AES key
    key = get_random_bytes(block_size)

    return key


def sign_input_text(sender_address: str, contract_address: str, function_selector: str, ct, key):
    function_selector_bytes = bytes.fromhex(function_selector[2:])

    # Ensure all input sizes are the correct length
    if len(sender_address) != address_size:
        raise ValueError(f"Invalid sender address length: {len(sender_address)} bytes, must be {address_size} bytes")
    if len(contract_address) != address_size:
        raise ValueError(f"Invalid contract address length: {len(contract_address)} bytes, must be {address_size} bytes")
    if len(function_selector_bytes) != function_selector_size:
        raise ValueError(f"Invalid signature size: {len(function_selector_bytes)} bytes, must be {function_selector_size} bytes")
    if len(ct) != ct_size:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be {ct_size} bytes")
    # Ensure the key is the correct length
    if len(key) != key_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {key_size} bytes")

    # Create the message to be signed by appending all inputs
    message = sender_address + contract_address + function_selector_bytes + ct

    return sign(message, key)


def sign_input_text_256(sender_address: str, contract_address: str, function_selector: str, ct, key):
    """
    Sign input text for 256-bit encrypted values.
    
    Similar to sign_input_text but accepts 64-byte ciphertext (CtUint256 blob).
    
    Args:
        sender_address: Address of the sender (20 bytes, without 0x prefix)
        contract_address: Address of the contract (20 bytes, without 0x prefix)
        function_selector: Function selector (hex string with 0x prefix, e.g., '0x12345678')
        ct: Ciphertext bytes (must be 64 bytes for uint256)
        key: Signing key (32 bytes)
    
    Returns:
        bytes: The signature
    
    Raises:
        ValueError: If any input has invalid length
    """
    function_selector_bytes = bytes.fromhex(function_selector[2:])

    if len(sender_address) != address_size:
        raise ValueError(f"Invalid sender address length: {len(sender_address)} bytes, must be {address_size} bytes")
    if len(contract_address) != address_size:
        raise ValueError(f"Invalid contract address length: {len(contract_address)} bytes, must be {address_size} bytes")
    if len(function_selector_bytes) != function_selector_size:
        raise ValueError(f"Invalid signature size: {len(function_selector_bytes)} bytes, must be {function_selector_size} bytes")
    
    # 256-bit IT has 64 bytes CT
    if len(ct) != 64:
        raise ValueError(f"Invalid ct length: {len(ct)} bytes, must be 64 bytes for uint256")
    
    if len(key) != key_size:
        raise ValueError(f"Invalid key length: {len(key)} bytes, must be {key_size} bytes")

    message = sender_address + contract_address + function_selector_bytes + ct

    return sign(message, key)


def sign(message, key):
    # Sign the message
    pk = keys.PrivateKey(key)
    signature = pk.sign_msg(message).to_bytes()

    return signature


def build_input_text(plaintext: int, user_aes_key: str, sender_address: str, contract_address: str, function_selector: str, signing_key: str) -> ItUint:
    # Convert the integer to a byte slice with size aligned to 8.
    plaintext_bytes = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big')

    # Encrypt the plaintext with the user's AES key
    ciphertext, r = encrypt(bytes.fromhex(user_aes_key), plaintext_bytes)
    ct = ciphertext + r

    # Sign the message
    signature = sign_input_text(bytes.fromhex(sender_address[2:]), bytes.fromhex(contract_address[2:]), function_selector, ct, signing_key)

    # Convert the ct to an integer
    int_cipher_text = int.from_bytes(ct, byteorder='big')

    return {
        'ciphertext': int_cipher_text,
        'signature': signature
    }


def build_string_input_text(plaintext: str, user_aes_key: str, sender_address: str, contract_address: str, function_selector: str, signing_key: str) -> ItString:
    input_text = {
        'ciphertext': {
            'value': []
        },
        'signature': []
    }

    encoded_plaintext = bytearray(list(plaintext.encode('utf-8')))

    for start_idx in range(0, len(encoded_plaintext), 8):
        end_idx = min(start_idx + 8, len(encoded_plaintext))

        byte_arr = encoded_plaintext[start_idx:end_idx] + bytearray(8 - (end_idx - start_idx))

        it_int = build_input_text(
            int.from_bytes(byte_arr, 'big'),
            user_aes_key,
            sender_address,
            contract_address,
            function_selector,
            signing_key
        )

        input_text['ciphertext']['value'].append(it_int['ciphertext'])
        input_text['signature'].append(it_int['signature'])
    
    return input_text


def decrypt_uint(ciphertext: CtUint, user_aes_key: str) -> int:
    # Convert ct to bytes (big-endian)
    byte_array = ciphertext.to_bytes(32, byteorder='big')

    # Split ct into two 128-bit arrays r and cipher
    cipher = byte_array[:block_size]
    r = byte_array[block_size:]

    # Decrypt the cipher
    decrypted_message = decrypt(bytes.fromhex(user_aes_key), r, cipher)

    # Print the decrypted cipher
    decrypted_uint = int.from_bytes(decrypted_message, 'big')

    return decrypted_uint


def create_ciphertext_256(plaintext_int: int, user_aes_key_bytes: bytes) -> bytes:
    """
    Create a 256-bit ciphertext by encrypting high and low 128-bit parts separately.
    
    Args:
        plaintext_int: Integer value to encrypt (must fit in 256 bits)
        user_aes_key_bytes: AES encryption key (16 bytes)
    
    Returns:
        bytes: 64-byte ciphertext blob formatted as:
               [high_ciphertext(16) | high_r(16) | low_ciphertext(16) | low_r(16)]
    
    Raises:
        ValueError: If plaintext exceeds 256 bits
    """
    # Convert 256-bit int to 32 bytes (Big Endian)
    try:
        plaintext_bytes = plaintext_int.to_bytes(32, 'big')
    except OverflowError:
        raise ValueError("Plaintext size must be 256 bits or smaller.")

    # Split into High and Low 128-bit parts
    high_bytes = plaintext_bytes[:16]
    low_bytes = plaintext_bytes[16:]

    # Encrypt High
    high_ct, high_r = encrypt(user_aes_key_bytes, high_bytes)
    
    # Encrypt Low
    low_ct, low_r = encrypt(user_aes_key_bytes, low_bytes)

    # Construct format: high.ciphertext + high.r + low.ciphertext + low.r
    return high_ct + high_r + low_ct + low_r


def prepare_it_256(plaintext: int, user_aes_key: str, sender_address: str, contract_address: str, function_selector: str, signing_key: str) -> ItUint256:
    """
    Prepare Input Text for a 256-bit encrypted integer.
    
    Encrypts a 256-bit integer and creates a signed Input Text structure
    suitable for smart contract interaction.
    
    Args:
        plaintext: Integer value to encrypt (must fit in 256 bits)
        user_aes_key: AES encryption key (hex string without 0x prefix, 32 hex chars)
        sender_address: Address of the sender (hex string with 0x prefix, 40 hex chars)
        contract_address: Address of the contract (hex string with 0x prefix, 40 hex chars)
        function_selector: Function selector (hex string with 0x prefix, e.g., '0x12345678')
        signing_key: Private key for signing (32 bytes)
    
    Returns:
        ItUint256: Dictionary containing ciphertext (ciphertextHigh, ciphertextLow) and signature
    
    Raises:
        ValueError: If plaintext exceeds 256 bits
    """
    if plaintext.bit_length() > 256:
        raise ValueError("Plaintext size must be 256 bits or smaller.")

    user_aes_key_bytes = bytes.fromhex(user_aes_key)
    
    ct_blob = create_ciphertext_256(plaintext, user_aes_key_bytes)
    
    # Split for types
    # ct_blob is 64 bytes: [high_ct(16) | high_r(16) | low_ct(16) | low_r(16)]
    high_blob = ct_blob[:32]
    low_blob = ct_blob[32:]

    # Sign the full 64-byte blob
    signature = sign_input_text_256(
        bytes.fromhex(sender_address[2:]), 
        bytes.fromhex(contract_address[2:]), 
        function_selector, 
        ct_blob, 
        signing_key
    )

    return {
        'ciphertext': {
            'ciphertextHigh': int.from_bytes(high_blob, 'big'),
            'ciphertextLow': int.from_bytes(low_blob, 'big')
        },
        'signature': signature
    }


def decrypt_uint256(ciphertext: CtUint256, user_aes_key: str) -> int:
    """
    Decrypt a 256-bit encrypted integer.
    
    Decrypts both high and low 128-bit parts and combines them back into
    a single 256-bit integer.
    
    Args:
        ciphertext: CtUint256 dictionary containing ciphertextHigh and ciphertextLow
        user_aes_key: AES decryption key (hex string without 0x prefix, 32 hex chars)
    
    Returns:
        int: The decrypted 256-bit integer value
    """
    user_aes_key_bytes = bytes.fromhex(user_aes_key)
    
    # Process High
    ct_high_int = ciphertext['ciphertextHigh']
    ct_high_bytes = ct_high_int.to_bytes(32, 'big')
    cipher_high = ct_high_bytes[:block_size]
    r_high = ct_high_bytes[block_size:]
    
    plaintext_high = decrypt(user_aes_key_bytes, r_high, cipher_high)

    # Process Low
    ct_low_int = ciphertext['ciphertextLow']
    ct_low_bytes = ct_low_int.to_bytes(32, 'big')
    cipher_low = ct_low_bytes[:block_size]
    r_low = ct_low_bytes[block_size:]
    
    plaintext_low = decrypt(user_aes_key_bytes, r_low, cipher_low)

    # Combine back to 256-bit int
    # High part is MSB
    full_bytes = plaintext_high + plaintext_low
    return int.from_bytes(full_bytes, 'big')


def decrypt_string(ciphertext: CtString, user_aes_key: str) -> str:
    if 'value' in ciphertext or hasattr(ciphertext, 'value'): # format when reading ciphertext from an event
        __ciphertext = ciphertext['value']
    elif isinstance(ciphertext, tuple): # format when reading ciphertext from state variable
        __ciphertext = ciphertext[0]
    else:
        raise RuntimeError('Unrecognized ciphertext format')

    decrypted_string = ""

    for value in __ciphertext:
        decrypted = decrypt_uint(value, user_aes_key)

        byte_length = (decrypted.bit_length() + 7) // 8  # calculate the byte length

        # Convert the integer to bytes
        decrypted_bytes = decrypted.to_bytes(byte_length, byteorder='big')

        # Decode the bytes to a string
        decrypted_string += decrypted_bytes.decode('utf-8')
    
    return decrypted_string.strip('\0')


def generate_rsa_keypair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Get public key
    public_key = private_key.public_key()
    # Serialize public key
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes


def decrypt_rsa(private_key_bytes: bytes, ciphertext: bytes):
    # Load private key
    private_key = serialization.load_der_private_key(private_key_bytes, password=None)
    # Decrypt ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


#This function recovers a user's key by decrypting two encrypted key shares with the given private key,
#and then XORing the two key shares together.
def recover_user_key(private_key_bytes: bytes, encrypted_key_share0: bytes, encrypted_key_share1: bytes):
    key_share0 = decrypt_rsa(private_key_bytes, encrypted_key_share0)
    key_share1 = decrypt_rsa(private_key_bytes, encrypted_key_share1)

    # XOR both key shares to get the user key
    return bytes([a ^ b for a, b in zip(key_share0, key_share1)])

