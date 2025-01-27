import tkinter as tk
from tkinter import messagebox

from singleBls.singleBlsAlg import BLS

# Initialize BLS instance and generate keys
bls = BLS()
sk, pk_exp, pk_numeric = bls.keygen()

sig_exp, sig_numeric = None, None  # Initialize signature variables


def create_gui():


    def sign():
        message = message_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        global sig_exp, sig_numeric
        sig_exp, sig_numeric = bls.sign_message(sk, message)  # Use BLS class method
        signed_message_label.config(
            text=f"Signature (exp): {sig_exp}\nSignature (numeric): {sig_numeric}"
        )

    def verify():
        message = verify_entry.get()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return

        if sig_exp is None:
            messagebox.showerror("Error", "Sign a message first!")
            return

        h_exp, left_side, right_side, is_valid = bls.verify_signature(pk_exp, message, sig_exp)  # Use BLS class method
        if is_valid:
            result_label.config(text="Verification Result: VALID", fg="green")
        else:
            result_label.config(text="Verification Result: INVALID", fg="red")
        verification_details_label.config(
            text=f"Hash Exponent: {h_exp}\nLeft Side: {left_side}\nRight Side: {right_side}"
        )

    # Root window
    root = tk.Tk()
    root.title("BLS Signature GUI")
    root.geometry("800x800")  # Adjusted window size
    root.configure(bg="#f4f4f4")

    # Key display
    keys_frame = tk.Frame(root, bg="#f4f4f4", pady=10)
    keys_frame.pack()

    tk.Label(keys_frame, text=f"Secret Key (sk): {sk}", font=("Helvetica", 16, "bold"), bg="#f4f4f4").pack()
    tk.Label(keys_frame, text=f"Public Key (exp): {pk_exp}\nPublic Key (numeric): {pk_numeric}",
             font=("Helvetica", 16), bg="#f4f4f4").pack()

    # Signing section
    sign_frame = tk.LabelFrame(root, text="Sign Message", font=("Helvetica", 16, "bold"), bg="#e9ecef", padx=20, pady=20)
    sign_frame.pack(pady=15, padx=10, fill="x")

    tk.Label(sign_frame, text="Message to Sign:", font=("Helvetica", 16), bg="#e9ecef").pack()
    message_entry = tk.Entry(sign_frame, width=60, font=("Helvetica", 16))
    message_entry.pack(pady=5)

    tk.Button(sign_frame, text="Sign Message", command=sign, font=("Helvetica", 16), bg="#4caf50", fg="white",
              activebackground="#45a049").pack(pady=10)

    signed_message_label = tk.Label(sign_frame, text="Signature: None", font=("Helvetica", 16), bg="#e9ecef", fg="#333")
    signed_message_label.pack()

    # Verification section with larger box
    verify_frame = tk.LabelFrame(root, text="Verify Message", font=("Helvetica", 16, "bold"), bg="#e9ecef", padx=20, pady=20)
    verify_frame.pack(pady=15, padx=20, fill="both", expand=True)  # Increased padding and fill

    tk.Label(verify_frame, text="Message to Verify:", font=("Helvetica", 16), bg="#e9ecef").pack()
    verify_entry = tk.Entry(verify_frame, width=60, font=("Helvetica", 16))  # Kept input box size constant
    verify_entry.pack(pady=5)

    tk.Button(verify_frame, text="Verify Signature", command=verify, font=("Helvetica", 16), bg="#2196f3", fg="white",
              activebackground="#1976d2").pack(pady=10)

    result_label = tk.Label(verify_frame, text="Verification Result: None", font=("Helvetica", 16, "bold"),
                            bg="#e9ecef", fg="#333")
    result_label.pack(pady=5)

    verification_details_label = tk.Label(verify_frame, text="", font=("Helvetica", 16), bg="#e9ecef", fg="#555")
    verification_details_label.pack(pady=10)

    root.mainloop()



def runSingleBls():
    gui = create_gui()
    gui.root.mainloop()


if __name__ == "__main__":
    # sig_exp, sig_numeric = None, None  # Initialize signature variables
    runSingleBls()
