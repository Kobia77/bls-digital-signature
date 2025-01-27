import tkinter as tk

from aggregateBls.aggregateBlsGui import runAggregateBls
from singleBls.singleBlsGui import runSingleBls


def launch_aggregate_gui(parent):
    runAggregateBls(parent)

def launch_single_gui():
    runSingleBls()

def main_menu():
    root = tk.Tk()
    root.title("BLS Signature Applications")
    root.geometry("400x200")
    root.configure(bg="#f4f4f4")

    tk.Label(
        root,
        text="BLS Signature Demo Menu",
        font=("Helvetica", 16, "bold"),
        bg="#f4f4f4"
    ).pack(pady=20)

    tk.Button(
        root,
        text="Aggregate BLS GUI",
        font=("Helvetica", 14),
        bg="#4caf50",
        fg="white",
        command=lambda: launch_aggregate_gui(root)
    ).pack(pady=10)

    tk.Button(
        root,
        text="Single BLS GUI",
        font=("Helvetica", 14),
        bg="#2196f3",
        fg="white",
        command=lambda: launch_single_gui()
    ).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main_menu()
