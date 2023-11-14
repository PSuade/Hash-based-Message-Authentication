import hmac
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from tkinter import *

def generate_random_key(length=32):
    return os.urandom(length)

def create_hmac(key, message, hash_algorithm='sha256'):
    hmac_obj = hmac.new(key, message, hash_algorithm)
    return hmac_obj.digest()

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce, ciphertext, tag

def decrypt_message(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

def submit():
    sender_name = sender_entry.get()
    recipient_name = recipient_entry.get()
    message_to_send = message_entry.get().encode()

    sender_secret_key = generate_random_key()
    hmac_value = create_hmac(sender_secret_key, message_to_send)
    shared_key = get_random_bytes(16)
    nonce, ciphertext, tag = encrypt_message(shared_key, message_to_send)

    received_message = decrypt_message(shared_key, nonce, ciphertext, tag)
    tamper_choice = tamper_var.get()

    if tamper_choice == "Yes":
        received_message += b"..tampered"

    receiver_secret_key = sender_secret_key
    tampered_hmac = create_hmac(receiver_secret_key, received_message)

    result_var.set("Message is authentic. It has not been tampered with." if hmac.compare_digest(hmac_value, tampered_hmac) else "Message has been tampered with.")
    encrypted_hex_var.set("Encrypted Message (hex):\nNonce: {}\nCiphertext: {}\nTag: {}".format(nonce.hex(), ciphertext.hex(), tag.hex()))
    received_message_var.set("Received Message:\n{}".format(received_message.decode()))

# Tkinter GUI setup
window = Tk()
window.title("Secure Messaging App")

sender_label = Label(window, text="Sender's Name:")
sender_label.grid(row=0, column=0)
sender_entry = Entry(window)
sender_entry.grid(row=0, column=1)

recipient_label = Label(window, text="Recipient's Name:")
recipient_label.grid(row=1, column=0)
recipient_entry = Entry(window)
recipient_entry.grid(row=1, column=1)

message_label = Label(window, text="Message:")
message_label.grid(row=2, column=0)
message_entry = Entry(window)
message_entry.grid(row=2, column=1)

tamper_label = Label(window, text="Tamper with the message?")
tamper_label.grid(row=3, column=0)
tamper_var = StringVar()
tamper_var.set("No")
tamper_radio_yes = Radiobutton(window, text="Yes", variable=tamper_var, value="Yes")
tamper_radio_yes.grid(row=3, column=1)
tamper_radio_no = Radiobutton(window, text="No", variable=tamper_var, value="No")
tamper_radio_no.grid(row=3, column=2)

submit_button = Button(window, text="Submit", command=submit)
submit_button.grid(row=4, column=0, columnspan=3)

result_var = StringVar()
result_label = Label(window, textvariable=result_var)
result_label.grid(row=5, column=0, columnspan=3)

# Labels for encrypted hex value, nonce, ciphertext, tag, and received message
encrypted_hex_var = StringVar()
encrypted_hex_label = Label(window, textvariable=encrypted_hex_var, justify=LEFT)
encrypted_hex_label.grid(row=6, column=0, columnspan=3)

received_message_var = StringVar()
received_message_label = Label(window, textvariable=received_message_var, justify=LEFT)
received_message_label.grid(row=7, column=0, columnspan=3)

window.mainloop()
