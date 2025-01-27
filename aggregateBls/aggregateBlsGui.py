import tkinter as tk
from tkinter import messagebox, ttk

from aggregateBls.aggregateBlsAlg import BLSAggregate, Signer


class BLSAggregateGUI:
    def __init__(self, parent):
        self.bls = BLSAggregate()
        self.signers = {}

        self.root = tk.Toplevel(parent)  # Use Toplevel instead of Tk
        self.root.title("BLS Aggregate Signature Demo")
        self.root.geometry("1000x800")
        self.root.configure(bg="#f4f4f4")

        # Setup GUI components
        self.setup_gui()

    def setup_gui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)
        self.setup_signer_tab()
        self.setup_signing_tab()
        self.setup_aggregate_tab()

    def setup_signer_tab(self):
        # Configure Treeview style for larger font
        style = ttk.Style()
        style.configure("Treeview", font=("Arial", 14))  # Font for rows
        style.configure("Treeview.Heading", font=("Arial", 16, "bold"))  # Font for headers

        signer_frame = ttk.Frame(self.notebook)
        self.notebook.add(signer_frame, text="Manage Signers")

        # Add Signer section
        add_frame = ttk.LabelFrame(signer_frame, text="Add New Signer")
        add_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(add_frame, text="Signer Name:", font=("Arial", 14)).pack(side=tk.LEFT, padx=5)
        self.signer_entry = ttk.Entry(add_frame, width=20, font=("Arial", 14))
        self.signer_entry.pack(side=tk.LEFT, padx=5)

        add_button = tk.Button(
            add_frame, text="Add Signer", command=self.add_signer, bg="#4CAF50", fg="white", font=("Arial", 14),
            height=1, width=12
        )
        add_button.pack(side=tk.LEFT, padx=5)

        # Signer List section
        list_frame = ttk.LabelFrame(signer_frame, text="Registered Signers")
        list_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.signer_tree = ttk.Treeview(list_frame, columns=("Name", "Public Key"), show="headings")
        self.signer_tree.heading("Name", text="Signer Name")
        self.signer_tree.heading("Public Key", text="Public Key")
        self.signer_tree.pack(pady=5, fill="both", expand=True)

    def setup_signing_tab(self):
        # Configure Treeview style for larger font
        style = ttk.Style()
        style.configure("Treeview", font=("Arial", 14))  # Font for rows
        style.configure("Treeview.Heading", font=("Arial", 16, "bold"))  # Font for headers

        signing_frame = ttk.Frame(self.notebook)
        self.notebook.add(signing_frame, text="Sign Messages")

        # Signing controls
        controls_frame = ttk.LabelFrame(signing_frame, text="Sign New Message")
        controls_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(controls_frame, text="Select Signer:", font=("Arial", 14)).pack(pady=5)
        self.signer_var = tk.StringVar()
        self.signer_menu = ttk.Combobox(controls_frame, textvariable=self.signer_var, font=("Arial", 14))
        self.signer_menu.pack(pady=5)

        ttk.Label(controls_frame, text="Message:", font=("Arial", 14)).pack(pady=5)
        self.message_entry = ttk.Entry(controls_frame, width=50, font=("Arial", 14))
        self.message_entry.pack(pady=5)

        sign_button = tk.Button(
            controls_frame, text="Sign Message", command=self.sign_message, bg="#2196F3", fg="white",
            font=("Arial", 14), height=1, width=15
        )
        sign_button.pack(pady=10)

        # Signatures display
        signatures_frame = ttk.LabelFrame(signing_frame, text="Signed Messages")
        signatures_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.signatures_tree = ttk.Treeview(signatures_frame, columns=("Signer", "Message", "Signature"),
                                            show="headings")
        self.signatures_tree.heading("Signer", text="Signer")
        self.signatures_tree.heading("Message", text="Message")
        self.signatures_tree.heading("Signature", text="Signature")
        self.signatures_tree.pack(pady=5, fill="both", expand=True)

    def setup_aggregate_tab(self):
        aggregate_frame = ttk.Frame(self.notebook)
        self.notebook.add(aggregate_frame, text="Aggregate & Verify")

        # Aggregate section
        agg_frame = ttk.LabelFrame(aggregate_frame, text="Aggregate Signatures")
        agg_frame.pack(pady=10, padx=10, fill="x")

        aggregate_button = tk.Button(
            agg_frame, text="Aggregate All Signatures",
            command=self.aggregate_signatures, bg="#FF9800", fg="white", font=("Arial", 14), height=1, width=25
        )
        aggregate_button.pack(pady=10)

        self.aggregate_text = tk.Text(agg_frame, height=8, width=80, font=("Arial", 14))
        self.aggregate_text.pack(pady=10)
        self.aggregate_text.bind("<Key>", lambda e: "break")  # Disable keyboard input

        verify_frame = ttk.LabelFrame(aggregate_frame, text="Verify Aggregate Signature")
        verify_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(verify_frame, text="Enter Tampered Message (Optional):", font=("Arial", 14)).pack(pady=5)
        self.tampered_message_entry = ttk.Entry(verify_frame, width=50, font=("Arial", 14))
        self.tampered_message_entry.pack(pady=5)

        verify_button = tk.Button(
            verify_frame, text="Verify Aggregate Signature",
            command=self.verify_aggregate, bg="#F44336", fg="white", font=("Arial", 14), height=1, width=25
        )
        verify_button.pack(pady=10)

        self.verify_text = tk.Text(verify_frame, height=12, width=80, font=("Arial", 14))
        self.verify_text.pack(pady=10)
        self.verify_text.bind("<Key>", lambda e: "break")

    def add_signer(self):
        name = self.signer_entry.get()
        if name and name not in self.signers:
            signer = Signer(self.bls, name)
            self.signers[name] = signer
            self.signer_tree.insert("", tk.END, values=(name, signer.pk_exp))
            self.signer_menu['values'] = list(self.signers.keys())
            self.signer_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Invalid or duplicate signer name!")

    def sign_message(self):
        signer_name = self.signer_var.get()
        message = self.message_entry.get()

        if not signer_name or not message:
            messagebox.showerror("Error", "Select signer and enter message!")
            return

        signer = self.signers[signer_name]
        sig_exp, sig_numeric = signer.sign_message(message)

        self.signatures_tree.insert("", tk.END, values=(signer_name, message, f"{sig_exp}"))
        self.message_entry.delete(0, tk.END)

    def aggregate_signatures(self):
        """
        Aggregate all signatures from all signers.
        """
        agg_sig_exp = 0  # Start with 0 for the aggregated exponent
        self.aggregate_text.delete(1.0, tk.END)  # Clear the previous aggregate text

        if not any(signer.signatures for signer in self.signers.values()):  # Check if signatures exist
            messagebox.showerror("Error", "No signatures to aggregate!")
            return

        # Sum all signature exponents from all signers
        for signer in self.signers.values():
            for sig_exp, _ in signer.signatures:
                agg_sig_exp = (agg_sig_exp + sig_exp) % self.bls.r

        agg_sig_numeric = self.bls.compute_g1_element(agg_sig_exp)

        # Display the aggregate signature
        self.aggregate_text.insert(
            tk.END,
            f"Aggregate Signature (exp): {agg_sig_exp}\nNumeric: {agg_sig_numeric}",
        )
        self.agg_sig_exp = agg_sig_exp  # Store for verification

    def verify_aggregate(self):
        """
        Verify the aggregate signature by comparing the pairing results.
        """
        if not hasattr(self, 'agg_sig_exp'):
            messagebox.showerror("Error", "No aggregate signature to verify!")
            return

        tampered_message = self.tampered_message_entry.get().strip()

        left_side = self.bls.pairing_function(self.agg_sig_exp, 1)  # Pairing of aggregate signature

        right_side = 0  # Start with 0 for the aggregated pairing result
        per_signer_results = []  # To store individual signer verification results

        # Loop through all signers and their signed messages
        for signer in self.signers.values():
            for message in signer.messages:
                # Use the tampered message if provided, else the original message
                current_message = tampered_message if tampered_message else message
                h_exp = self.bls.hash_to_exponent(current_message)
                signer_pairing = self.bls.pairing_function(h_exp, signer.pk_exp)
                right_side = (right_side + signer_pairing) % self.bls.r

                # Verify individual signatures
                is_signer_valid = signer_pairing == self.bls.pairing_function(
                    self.bls.hash_to_exponent(message), signer.pk_exp
                )
                per_signer_results.append((signer.name, message, is_signer_valid))

        # Check if the aggregate signature is valid
        is_valid = (left_side == right_side)

        # Generate detailed results
        result_text = f"Overall Verification {'SUCCESSFUL' if is_valid else 'FAILED'}\n" \
                      f"Left Side: {left_side}\nRight Side: {right_side}\n\n" \
                      f"Per-Signer Results:\n"

        for signer_name, signed_message, result in per_signer_results:
            status = "SUCCESSFUL" if result else "FAILED"
            result_text += f"- Signer: {signer_name}, Message: '{signed_message}', Verification: {status}\n"

        # Display the verification results
        self.verify_text.delete(1.0, tk.END)
        self.verify_text.insert(tk.END, result_text)


def runAggregateBls(parent):
    BLSAggregateGUI(parent)


if __name__ == "__main__":
    runAggregateBls()
