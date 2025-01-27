import tkinter as tk
from tkinter import messagebox

# Functions from your BLS-like implementation
import hashlib
import random

def mod_exp(base, exp, modulus):
    result = 1
    cur = base % modulus
    e = exp
    while e > 0:
        if (e & 1) == 1:
            result = (result * cur) % modulus
        cur = (cur * cur) % modulus
        e >>= 1
    return result

def hash_to_exponent(message):
    h = hashlib.sha256(message.encode('utf-8')).digest()
    num = int.from_bytes(h, 'big')
    return num % r

def compute_g1_element(exponent):
    return mod_exp(g1, exponent, P)

def compute_g2_element(exponent):
    return mod_exp(g2, exponent, P)

def pairing_function(exp_g1, exp_g2):
    return (exp_g1 * exp_g2) % r

def keygen():
    sk = random.randrange(1, r)
    pk_exp = sk
    pk_numeric = compute_g2_element(pk_exp)
    return sk, pk_exp, pk_numeric

def sign_message(sk, message):
    h_exp = hash_to_exponent(message)
    sig_exp = (h_exp * sk) % r
    sig_numeric = compute_g1_element(sig_exp)
    return sig_exp, sig_numeric

def verify_signature(pk_exp, message, sig_exp):
    h_exp = hash_to_exponent(message)
    left_side = pairing_function(sig_exp, 1)
    right_side = pairing_function(h_exp, pk_exp)
    print(f"Verification Process:\nHash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}")
    return h_exp, left_side, right_side, (left_side == right_side)

# Global Constants for the BLS-like scheme
P = 2**127 - 1
r = P - 1
g1 = 5
g2 = 7
g_t = 11

# Generate keys
sk, pk_exp, pk_numeric = keygen()

# GUI implementation
def create_gui():
    def sign():
        message = message_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        global sig_exp, sig_numeric
        sig_exp, sig_numeric = sign_message(sk, message)
        signed_message_label.config(text=f"Signature (exp): {sig_exp}\nSignature (numeric): {sig_numeric}")

    def verify():
        message = verify_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        if sig_exp is None:
            messagebox.showerror("Error", "Sign a message first!")
            return

        h_exp, left_side, right_side, is_valid = verify_signature(pk_exp, message, sig_exp)
        result_label.config(text=f"Verification Result: {'Valid' if is_valid else 'Invalid'}")
        verification_details_label.config(
            text=f"Hash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}"
        )

    # Root window
    root = tk.Tk()
    root.title("BLS-Like Signature GUI")

    # Key display
    keys_frame = tk.Frame(root)
    keys_frame.pack(pady=10)

    tk.Label(keys_frame, text=f"Secret Key (sk): {sk}").pack()
    tk.Label(keys_frame, text=f"Public Key (exp): {pk_exp}\nPublic Key (numeric): {pk_numeric}").pack()

    # Signing section
    sign_frame = tk.Frame(root)
    sign_frame.pack(pady=10)

    tk.Label(sign_frame, text="Message to Sign:").pack()
    message_entry = tk.Entry(sign_frame, width=50)
    message_entry.pack()

    tk.Button(sign_frame, text="Sign Message", command=sign).pack()

    signed_message_label = tk.Label(sign_frame, text="Signature: None")
    signed_message_label.pack()

    # Verification section
    verify_frame = tk.Frame(root)
    verify_frame.pack(pady=10)

    tk.Label(verify_frame, text="Message to Verify:").pack()
    verify_entry = tk.Entry(verify_frame, width=50)
    verify_entry.pack()

    tk.Button(verify_frame, text="Verify Signature", command=verify).pack()

    result_label = tk.Label(verify_frame, text="Verification Result: None")
    result_label.pack()

    verification_details_label = tk.Label(verify_frame, text="")
    verification_details_label.pack()

    root.mainloop()

# Run the GUI
if __name__ == "__main__":
    sig_exp, sig_numeric = None, None
    create_gui()
