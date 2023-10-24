import hmac
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Function to generate a random secret key
def generate_random_key(length=32):
    return os.urandom(length)

# Function to create an HMAC for a message using a secret key
def create_hmac(key, message, hash_algorithm='sha256'):
    hmac_obj = hmac.new(key, message, hash_algorithm)
    return hmac_obj.digest()

# Function to encrypt a message with AES
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce, ciphertext, tag

# Function to decrypt an encrypted message with AES
def decrypt_message(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

def main():
    # Sender's perspective
    # Generate a random secret key and store it securely
    sender_secret_key = generate_random_key()

    #Enter senders name
    sender_name = input("Enter sender's name: ")

    # Receive recipient's name and message from the user
    recipient_name = input("Enter recipient's name: ")
    message_to_send = input("Enter the message you want to send: ").encode()
    print(f"{sender_name} has sent message to: {recipient_name}")

    # Create an HMAC for the message
    hmac_value = create_hmac(sender_secret_key, message_to_send)

    # Encrypt the message
    shared_key = get_random_bytes(16)  # AES key
    nonce, ciphertext, tag = encrypt_message(shared_key, message_to_send)

    # Print the encrypted message
    print("Encrypted Message (hex):")
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    # Send the recipient's name, HMAC, and the encrypted message

    # Receiver's perspective
    # Receive the recipient's name, HMAC, and the encrypted message

    # Verify the HMAC
    receiver_secret_key = sender_secret_key  # Receiver has the same secret key

    received_message = decrypt_message(shared_key, nonce, ciphertext, tag)
    received_hmac = create_hmac(receiver_secret_key, received_message)

    # Compare the received HMAC with the calculated HMAC
    if hmac.compare_digest(hmac_value, received_hmac):
        print("Message is authentic. It has not been tampered with.")
        print("Received Message:", received_message.decode())
    else:
        print("Message may have been tampered with. Do not trust it.")

if __name__ == "__main__":
    main()
