import tkinter as tk
from tkinter import messagebox

# Functions from your BLS-like implementation
import hashlib
import random

"""
======================================================================
BLS-LIKE SIGNATURE IMPLEMENTATION
======================================================================
Disclaimers:
1) This code is for demonstration and is not intended for production use.
2) In a real BLS scheme, you'd use an elliptic curve (like BLS12-381),
   implement a proper bilinear pairing, and use a secure hash-to-curve.
3) The parameter sizes and operations here are illustrative. 
4) Do NOT use this code in any real production environment!
======================================================================
"""


def mod_exp(base, exp, modulus):
    """
    Fast exponentiation: (base^exp) mod modulus.
    """
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
    """
    Hash the message (SHA256) and convert to an integer mod r.
    This represents a simplified exponent in G1.
    """
    h = hashlib.sha256(message.encode('utf-8')).digest()
    num = int.from_bytes(h, 'big')
    return num % r


def compute_g1_element(exponent):
    """
    Numeric representation of a G1 point: g1^exponent mod P (simplified).
    """
    return mod_exp(g1, exponent, P)


def compute_g2_element(exponent):
    """
    Numeric representation of a G2 point: g2^exponent mod P (simplified).
    """
    return mod_exp(g2, exponent, P)


def pairing_function(exp_g1, exp_g2):
    """
    Demonstration of a bilinear pairing e: G1 x G2 -> GT in exponent form.
    Here, we simply compute (exp_g1 * exp_g2) mod r as the pairing exponent.
    """
    return (exp_g1 * exp_g2) % r


def keygen():
    """
    Generate a secret key 'sk' in [1, r-1].
    The public key in real BLS is pk = g2^sk in G2.
    Here, pk_exp = sk as an exponent representation for demonstration,
    and pk_numeric is g2^sk mod P (not strictly needed for the logic).
    """
    sk = random.randrange(1, r)
    pk_exp = sk
    pk_numeric = compute_g2_element(pk_exp)
    return sk, pk_exp, pk_numeric


def sign_message(sk, message):
    """
    In real BLS: signature = H(m)^sk in G1.
    Here, we do sig_exp = (hashExp(m) * sk) mod r as an exponent.
    The numeric form is g1^sig_exp mod P.
    """
    h_exp = hash_to_exponent(message)
    sig_exp = (h_exp * sk) % r
    sig_numeric = compute_g1_element(sig_exp)
    return sig_exp, sig_numeric


def verify_signature(pk_exp, message, sig_exp):
    """
    Real BLS: check e(sig, g2) == e(H(m), pk).
    Demonstration version in exponent form:
      left_side  = pairing_function(sig_exp, 1) = sig_exp
      right_side = pairing_function(h_exp, pk_exp) = h_exp * pk_exp mod r
    If they match, the signature is valid.
    """
    h_exp = hash_to_exponent(message)
    left_side = pairing_function(sig_exp, 1)
    right_side = pairing_function(h_exp, pk_exp)
    print(f"Verification Process:\nHash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}")
    return h_exp, left_side, right_side, (left_side == right_side)


# ==============================================

# Global Constants for the BLS-like scheme
# A large(ish) prime for the modulus.
# In a real scenario, you would use a special prime for the chosen curve (e.g., 381-bit prime).
P = 2 ** 127 - 1

# We define a group order r in a simplified way. In real usage,
# r would be the prime subgroup order of the elliptic curve.
r = P - 1

# "Generators" in a simplified sense for G1, G2, and GT.
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
    root.geometry("800x600")

    # Key display
    keys_frame = tk.Frame(root)
    keys_frame.pack(pady=10)

    tk.Label(keys_frame, text=f"Secret Key (sk): {sk}", font=("Helvetica", 14)).pack()
    tk.Label(keys_frame, text=f"Public Key (exp): {pk_exp}\nPublic Key (numeric): {pk_numeric}",
             font=("Helvetica", 14)).pack()

    # Signing section
    sign_frame = tk.Frame(root)
    sign_frame.pack(pady=10)

    tk.Label(sign_frame, text="Message to Sign:", font=("Helvetica", 14)).pack()
    message_entry = tk.Entry(sign_frame, width=50, font=("Helvetica", 14))
    message_entry.pack()

    tk.Button(sign_frame, text="Sign Message", command=sign, font=("Helvetica", 14)).pack()

    signed_message_label = tk.Label(sign_frame, text="Signature: None", font=("Helvetica", 14))
    signed_message_label.pack()

    # Verification section
    verify_frame = tk.Frame(root)
    verify_frame.pack(pady=10)

    tk.Label(verify_frame, text="Message to Verify:", font=("Helvetica", 14)).pack()
    verify_entry = tk.Entry(verify_frame, width=50, font=("Helvetica", 14))
    verify_entry.pack()

    tk.Button(verify_frame, text="Verify Signature", command=verify, font=("Helvetica", 14)).pack()

    result_label = tk.Label(verify_frame, text="Verification Result: None", font=("Helvetica", 14))
    result_label.pack()

    verification_details_label = tk.Label(verify_frame, text="", font=("Helvetica", 14))
    verification_details_label.pack()

    root.mainloop()


# Run the GUI
if __name__ == "__main__":
    sig_exp, sig_numeric = None, None
    create_gui()
