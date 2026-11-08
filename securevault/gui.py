"""Tkinter GUI for SecureVault."""

from __future__ import annotations

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .core import decrypt_file, encrypt_file


class SecureVaultApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SecureVault")
        self.geometry("720x420")
        self.minsize(620, 360)
        self.configure(padx=24, pady=22)

        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()

        self._build_ui()

    def _build_ui(self) -> None:
        title = ttk.Label(self, text="SecureVault File Protector", font=("Segoe UI", 18, "bold"))
        title.pack(anchor="w", pady=(0, 16))

        subtitle = ttk.Label(
            self,
            text="Encrypt or decrypt any file using a password.",
            font=("Segoe UI", 10),
        )
        subtitle.pack(anchor="w", pady=(0, 16))

        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(input_frame, text="Input file:", width=14, anchor="w").pack(side="left")
        ttk.Entry(input_frame, textvariable=self.input_path, width=60).pack(side="left", fill="x", expand=True, padx=(10, 8))
        ttk.Button(input_frame, text="Browse", command=self.choose_input_file).pack(side="left")

        output_frame = ttk.Frame(self)
        output_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(output_frame, text="Output file:", width=14, anchor="w").pack(side="left")
        ttk.Entry(output_frame, textvariable=self.output_path, width=60).pack(side="left", fill="x", expand=True, padx=(10, 8))
        ttk.Button(output_frame, text="Save As", command=self.choose_output_file).pack(side="left")

        password_frame = ttk.Frame(self)
        password_frame.pack(fill="x", pady=(0, 16))
        ttk.Label(password_frame, text="Password:", width=14, anchor="w").pack(side="left")
        ttk.Entry(password_frame, textvariable=self.password, width=60, show="*", font=("Segoe UI", 10)).pack(side="left", fill="x", expand=True, padx=(10, 8))

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 14))
        ttk.Button(actions, text="Encrypt File", command=lambda: self.process_file("encrypt")).pack(side="left", padx=(0, 12))
        ttk.Button(actions, text="Decrypt File", command=lambda: self.process_file("decrypt")).pack(side="left")

        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status, foreground="#145DA0").pack(anchor="w", pady=(8, 0))

    def choose_input_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a file to encrypt or decrypt")
        if path:
            self.input_path.set(path)
            if not self.output_path.get():
                target = Path(path)
                self.output_path.set(str(target.parent / f"{target.stem}.securevault"))

    def choose_output_file(self) -> None:
        path = filedialog.asksaveasfilename(title="Choose output location")
        if path:
            self.output_path.set(path)

    def process_file(self, mode: str) -> None:
        source = self.input_path.get().strip()
        destination = self.output_path.get().strip()
        password = self.password.get()

        if not source or not os.path.exists(source):
            messagebox.showerror("Error", "Please choose a valid input file.")
            return
        if not destination:
            messagebox.showerror("Error", "Please choose an output file path.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        try:
            if mode == "encrypt":
                encrypt_file(source, destination, password)
                self.status.set(f"Encrypted: {source} -> {destination}")
            else:
                decrypt_file(source, destination, password)
                self.status.set(f"Decrypted: {source} -> {destination}")
            messagebox.showinfo("Success", f"Operation completed successfully: {mode.upper()}.")
        except Exception as exc:  # pragma: no cover - GUI error handling
            self.status.set(f"Error: {exc}")
            messagebox.showerror("Error", str(exc))


def launch_gui() -> None:
    app = SecureVaultApp()
    app.mainloop()
