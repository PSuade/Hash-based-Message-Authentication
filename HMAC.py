import hmac
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk

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

#Secret key used for HMAC creation
secret_key = generate_random_key()

# Shared key for both sender and receiver
shared_key = get_random_bytes(16)

# Global variable for hmac_value
hmac_value = None

def generate_and_send_message():
    global hmac_value  # Use the global hmac_value

    
    sender_name = sender_name_entry.get()
    recipient_name = recipient_name_entry.get()
    message = message_entry.get().encode()

    hmac_value = create_hmac(secret_key, message)
    nonce, ciphertext, tag = encrypt_message(shared_key, message)

    # Update the GUI to display results
    result_label.config(text=f"Message sent from {sender_name} to {recipient_name}")

    # Print the encrypted message
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Encrypted Message (hex):\n")
    result_text.insert(tk.END, f"Nonce: {nonce.hex()}\n")
    result_text.insert(tk.END, f"Ciphertext: {ciphertext.hex()}\n")
    result_text.insert(tk.END, f"Tag: {tag.hex()}")

    # Sending the recipient_name, hmac_value, and encrypted message
    # (You would send these values through a network or another channel)
    # In a real-world scenario, you'd send these values to the recipient

def receive_and_verify_message():
    global hmac_value  # Use the global hmac_value

    # This part would be executed on the receiver's side
    # Here, you would receive recipient_name, hmac_value, nonce, ciphertext, and tag

    # Extract nonce, ciphertext, and tag from the result_text
    extracted_values = result_text.get(1.0, tk.END).split("\n")[1:4]
    received_nonce = bytes.fromhex(extracted_values[0].split(":")[1].strip())  # Extract nonce
    received_ciphertext = bytes.fromhex(extracted_values[1].split(":")[1].strip())  # Extract ciphertext
    received_tag = bytes.fromhex(extracted_values[2].split(":")[1].strip())  # Extract tag

    # Decrypt the received message
    received_message = decrypt_message(shared_key, received_nonce, received_ciphertext, received_tag)

    # User prompt to decide whether to tamper with the received message
    tamper_choice = tamper_choice_var.get()

    if tamper_choice == "yes":
        additional_content = tamper_content_entry.get().encode()
        received_message += additional_content

    # Create an HMAC for the unaltered message
    hmac_value_original = create_hmac(secret_key, received_message)


    # Compare the received HMAC with the original HMAC
    if hmac.compare_digest(hmac_value, hmac_value_original):
        result_text.insert(tk.END, "\nMessage is authentic. It has not been tampered with.")
        result_text.insert(tk.END, f"\nReceived Message: {received_message.decode()}")
    else:
        result_text.insert(tk.END, "\nMessage has been tampered with.")
        result_text.insert(tk.END, f"\nReceived Message (Tampered): {received_message.decode()}")



# Create the GUI window
app = tk.Tk()
app.title("HMAC and Encryption Application")

# Create GUI components
sender_name_label = tk.Label(app, text="Sender's Name:")
sender_name_entry = tk.Entry(app)
recipient_name_label = tk.Label(app, text="Recipient's Name:")
recipient_name_entry = tk.Entry(app)
message_label = tk.Label(app, text="Message:")
message_entry = tk.Entry(app)

tamper_choice_var = tk.StringVar(value="no")
tamper_choice_label = tk.Label(app, text="Tamper with Received Message? (yes/no):")
tamper_choice_entry = tk.Entry(app, textvariable=tamper_choice_var)

tamper_content_label = tk.Label(app, text="Enter additional content to tamper (if yes):")
tamper_content_entry = tk.Entry(app)

send_button = tk.Button(app, text="Send Message", command=generate_and_send_message)
receive_button = tk.Button(app, text="Receive and Verify Message", command=receive_and_verify_message)

result_label = tk.Label(app, text="Result:")
result_text = tk.Text(app, height=15, width=50)

# Place components on the GUI
sender_name_label.grid(row=0, column=0)
sender_name_entry.grid(row=0, column=1)
recipient_name_label.grid(row=1, column=0)
recipient_name_entry.grid(row=1, column=1)
message_label.grid(row=2, column=0)
message_entry.grid(row=2, column=1)

tamper_choice_label.grid(row=3, column=0)
tamper_choice_entry.grid(row=3, column=1)
tamper_content_label.grid(row=4, column=0)
tamper_content_entry.grid(row=4, column=1)

send_button.grid(row=5, column=0, columnspan=2)
receive_button.grid(row=6, column=0, columnspan=2)
result_label.grid(row=7, column=0, columnspan=2)
result_text.grid(row=8, column=0, columnspan=2)

app.mainloop()


