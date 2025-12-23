import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from rsa import (
    b64d,
    b64e,
    bytes_to_text,
    decrypt_hybrid,
    encrypt_hybrid,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign_bytes,
    text_to_bytes,
    verify_bytes,
)

# ======================
# App state
# ======================
current_keypair = None
current_public_path = ""
current_private_path = ""
last_envelope = None

# ======================
# Helpers
# ======================

def read_input(text_widget: scrolledtext.ScrolledText, file_entry: tk.Entry) -> tuple[bytes, bool]:
    path = file_entry.get().strip()
    if path:
        with open(path, "rb") as f:
            return f.read(), True
    text = text_widget.get("1.0", tk.END).rstrip("\n")
    return text_to_bytes(text), False


def write_text_output(text_widget: scrolledtext.ScrolledText, data: bytes) -> None:
    try:
        text = bytes_to_text(data)
    except UnicodeDecodeError:
        text = data.hex()
        messagebox.showinfo("Info", "Binary data shown as hex.")
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, text)


def save_bytes(data: bytes, default_ext: str, filetypes: list[tuple[str, str]]) -> None:
    path = filedialog.asksaveasfilename(defaultextension=default_ext, filetypes=filetypes)
    if path:
        with open(path, "wb") as f:
            f.write(data)


def browse_file(entry: tk.Entry) -> None:
    path = filedialog.askopenfilename()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


# ======================
# Key management
# ======================

def generate_keys():
    global current_keypair, current_public_path, current_private_path
    try:
        bits = int(entry_bits.get())
        current_keypair = generate_keypair(bits)
        current_public_path = ""
        current_private_path = ""
        messagebox.showinfo("OK", f"Generated keypair ({bits} bits)")
    except Exception as exc:
        messagebox.showerror("Error", str(exc))


def save_current_public():
    global current_public_path
    if not current_keypair:
        messagebox.showwarning("Warning", "Generate keypair first")
        return
    path = filedialog.asksaveasfilename(defaultextension=".pub")
    if path:
        save_public_key(current_keypair.public, path)
        current_public_path = path
        messagebox.showinfo("OK", "Public key saved")


def save_current_private():
    global current_private_path
    if not current_keypair:
        messagebox.showwarning("Warning", "Generate keypair first")
        return
    path = filedialog.asksaveasfilename(defaultextension=".pri")
    if path:
        save_private_key(current_keypair.private, path)
        current_private_path = path
        messagebox.showinfo("OK", "Private key saved")


# ======================
# Encrypt / Decrypt
# ======================

def encrypt_ui():
    global last_envelope
    pub_path = entry_enc_pub.get().strip()
    if not pub_path:
        messagebox.showwarning("Warning", "Select public key for encryption")
        return
    try:
        pub = load_public_key(pub_path)
        data, _ = read_input(text_enc_input, entry_enc_file)
        envelope = encrypt_hybrid(data, pub, None)
        last_envelope = envelope
        obj = json.loads(envelope.decode("utf-8"))
        ct_only = obj.get("ct", "")
        text_enc_output.delete("1.0", tk.END)
        text_enc_output.insert(tk.END, ct_only)
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if save_path:
            with open(save_path, "wb") as f:
                f.write(envelope)
        messagebox.showinfo("OK", "Encrypted envelope created")
    except Exception as exc:
        messagebox.showerror("Error", str(exc))


def decrypt_ui():
    priv_path = entry_dec_priv.get().strip()
    if not priv_path:
        messagebox.showwarning("Warning", "Select private key for decryption")
        return
    try:
        priv = load_private_key(priv_path)
        blob, _ = read_input(text_dec_input, entry_dec_file)
        plaintext, _ = decrypt_hybrid(blob, priv, None, verify_sig=False)
        write_text_output(text_dec_output, plaintext)
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All files", "*.*")])
        if save_path:
            with open(save_path, "wb") as f:
                f.write(plaintext)
    except Exception as exc:
        messagebox.showerror("Error", str(exc))


def save_envelope_ui():
    if not last_envelope:
        messagebox.showwarning("Warning", "No envelope to save")
        return
    save_bytes(last_envelope, ".txt", [("Text", "*.txt"), ("All files", "*.*")])


def save_plaintext_ui():
    data = text_dec_output.get("1.0", tk.END).rstrip("\n")
    if not data:
        messagebox.showwarning("Warning", "No plaintext to save")
        return
    save_bytes(text_to_bytes(data), ".txt", [("Text", "*.txt"), ("All files", "*.*")])


# ======================
# Sign / Verify
# ======================

def sign_ui():
    priv_path = entry_sign_priv.get().strip()
    if not priv_path:
        messagebox.showwarning("Warning", "Select private key for signing")
        return
    try:
        priv = load_private_key(priv_path)
        data, _ = read_input(text_sign_input, entry_sign_file)
        sig = sign_bytes(data, priv)
        sig_b64 = b64e(sig)
        text_sign_output.delete("1.0", tk.END)
        text_sign_output.insert(tk.END, sig_b64)
        save_path = filedialog.asksaveasfilename(defaultextension=".sig", filetypes=[("Signature", "*.sig"), ("All files", "*.*")])
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(sig_b64)
    except Exception as exc:
        messagebox.showerror("Error", str(exc))


def verify_ui():
    pub_path = entry_verify_pub.get().strip()
    if not pub_path:
        messagebox.showwarning("Warning", "Select public key for verification")
        return
    try:
        pub = load_public_key(pub_path)
        data, _ = read_input(text_verify_input, entry_verify_file)
        sig_b64 = text_verify_sig.get("1.0", tk.END).strip()
        if not sig_b64:
            messagebox.showwarning("Warning", "Paste signature base64 or load signature file")
            return
        sig = b64d(sig_b64)
        ok = verify_bytes(data, sig, pub)
        if ok:
            messagebox.showinfo("Verify", "Signature VALID")
        else:
            messagebox.showerror("Verify", "Signature INVALID")
    except Exception as exc:
        messagebox.showerror("Error", str(exc))


def save_signature_ui():
    sig_b64 = text_sign_output.get("1.0", tk.END).strip()
    if not sig_b64:
        messagebox.showwarning("Warning", "No signature to save")
        return
    save_bytes(sig_b64.encode("utf-8"), ".sig", [("Signature", "*.sig"), ("All files", "*.*")])


def load_signature_file():
    path = filedialog.askopenfilename()
    if path:
        with open(path, "r", encoding="utf-8") as f:
            sig_b64 = f.read().strip()
        text_verify_sig.delete("1.0", tk.END)
        text_verify_sig.insert(tk.END, sig_b64)




# ======================
# Tkinter UI
# ======================
root = tk.Tk()
root.title("RSA Hybrid Demo (Educational)")
root.geometry("980x760")

frame_top = tk.Frame(root)
frame_top.pack(fill=tk.X, pady=5)

# Key panel
frame_keys = tk.LabelFrame(root, text="Step 1: Generate a keypair")
frame_keys.pack(fill=tk.X, padx=10, pady=5)

tk.Label(frame_keys, text="Key size (bits):").grid(row=0, column=0, padx=5, pady=5)
entry_bits = tk.Entry(frame_keys, width=8)
entry_bits.insert(0, "1024")
entry_bits.grid(row=0, column=1, padx=5, pady=5)

tk.Button(frame_keys, text="Generate", command=generate_keys).grid(row=0, column=2, padx=5, pady=5)
tk.Button(frame_keys, text="Save Public", command=save_current_public).grid(row=0, column=3, padx=5, pady=5)
tk.Button(frame_keys, text="Save Private", command=save_current_private).grid(row=0, column=4, padx=5, pady=5)

notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Encrypt tab
enc_tab = ttk.Frame(notebook)
notebook.add(enc_tab, text="Encrypt")

tk.Label(enc_tab, text="Plaintext / File").pack()
text_enc_input = scrolledtext.ScrolledText(enc_tab, height=7)
text_enc_input.pack(fill=tk.BOTH, expand=True, padx=10)

frame_enc_file = tk.Frame(enc_tab)
frame_enc_file.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_enc_file, text="Input file (optional):").pack(side=tk.LEFT)
entry_enc_file = tk.Entry(frame_enc_file)
entry_enc_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_enc_file, text="Browse", command=lambda: browse_file(entry_enc_file)).pack(side=tk.LEFT)

frame_enc_key = tk.Frame(enc_tab)
frame_enc_key.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_enc_key, text="Public key (recipient):").pack(side=tk.LEFT)
entry_enc_pub = tk.Entry(frame_enc_key)
entry_enc_pub.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_enc_key, text="Browse", command=lambda: browse_file(entry_enc_pub)).pack(side=tk.LEFT)

frame_enc_btn = tk.Frame(enc_tab)
frame_enc_btn.pack(pady=5)
tk.Button(frame_enc_btn, text="Encrypt", width=16, command=encrypt_ui).pack(side=tk.LEFT, padx=5)

tk.Label(enc_tab, text="Ciphertext").pack()
text_enc_output = scrolledtext.ScrolledText(enc_tab, height=6)
text_enc_output.pack(fill=tk.BOTH, expand=True, padx=10)

tk.Label(enc_tab, text="Envelope is saved when you click Encrypt.").pack()

# Decrypt tab
dec_tab = ttk.Frame(notebook)
notebook.add(dec_tab, text="Decrypt")

tk.Label(dec_tab, text="Envelope JSON / File").pack()
text_dec_input = scrolledtext.ScrolledText(dec_tab, height=7)
text_dec_input.pack(fill=tk.BOTH, expand=True, padx=10)

frame_dec_file = tk.Frame(dec_tab)
frame_dec_file.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_dec_file, text="Envelope file (optional):").pack(side=tk.LEFT)
entry_dec_file = tk.Entry(frame_dec_file)
entry_dec_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_dec_file, text="Browse", command=lambda: browse_file(entry_dec_file)).pack(side=tk.LEFT)

frame_dec_key = tk.Frame(dec_tab)
frame_dec_key.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_dec_key, text="Private key (recipient):").pack(side=tk.LEFT)
entry_dec_priv = tk.Entry(frame_dec_key)
entry_dec_priv.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_dec_key, text="Browse", command=lambda: browse_file(entry_dec_priv)).pack(side=tk.LEFT)

tk.Button(dec_tab, text="Decrypt", width=16, command=decrypt_ui).pack(pady=5)

tk.Label(dec_tab, text="Plaintext output").pack()
text_dec_output = scrolledtext.ScrolledText(dec_tab, height=7)
text_dec_output.pack(fill=tk.BOTH, expand=True, padx=10)

tk.Button(dec_tab, text="Save Plaintext", command=save_plaintext_ui).pack(pady=5)

# Sign tab
sign_tab = ttk.Frame(notebook)
notebook.add(sign_tab, text="Sign")

tk.Label(sign_tab, text="Message / File").pack()
text_sign_input = scrolledtext.ScrolledText(sign_tab, height=7)
text_sign_input.pack(fill=tk.BOTH, expand=True, padx=10)

frame_sign_file = tk.Frame(sign_tab)
frame_sign_file.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_sign_file, text="Input file (optional):").pack(side=tk.LEFT)
entry_sign_file = tk.Entry(frame_sign_file)
entry_sign_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_sign_file, text="Browse", command=lambda: browse_file(entry_sign_file)).pack(side=tk.LEFT)

frame_sign_key = tk.Frame(sign_tab)
frame_sign_key.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_sign_key, text="Private key (signer):").pack(side=tk.LEFT)
entry_sign_priv = tk.Entry(frame_sign_key)
entry_sign_priv.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_sign_key, text="Browse", command=lambda: browse_file(entry_sign_priv)).pack(side=tk.LEFT)

tk.Button(sign_tab, text="Sign", width=16, command=sign_ui).pack(pady=5)

tk.Label(sign_tab, text="Signature (Base64)").pack()
text_sign_output = scrolledtext.ScrolledText(sign_tab, height=6)
text_sign_output.pack(fill=tk.BOTH, expand=True, padx=10)

tk.Label(sign_tab, text="Signature is saved when you click Sign.").pack()

# Verify tab
verify_tab = ttk.Frame(notebook)
notebook.add(verify_tab, text="Verify")

tk.Label(verify_tab, text="Message / File").pack()
text_verify_input = scrolledtext.ScrolledText(verify_tab, height=7)
text_verify_input.pack(fill=tk.BOTH, expand=True, padx=10)

frame_verify_file = tk.Frame(verify_tab)
frame_verify_file.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_verify_file, text="Input file (optional):").pack(side=tk.LEFT)
entry_verify_file = tk.Entry(frame_verify_file)
entry_verify_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_verify_file, text="Browse", command=lambda: browse_file(entry_verify_file)).pack(side=tk.LEFT)

frame_verify_key = tk.Frame(verify_tab)
frame_verify_key.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_verify_key, text="Public key (signer):").pack(side=tk.LEFT)
entry_verify_pub = tk.Entry(frame_verify_key)
entry_verify_pub.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
tk.Button(frame_verify_key, text="Browse", command=lambda: browse_file(entry_verify_pub)).pack(side=tk.LEFT)

frame_verify_sig = tk.Frame(verify_tab)
frame_verify_sig.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_verify_sig, text="Signature (Base64):").pack(side=tk.LEFT)
tk.Button(frame_verify_sig, text="Load Signature File", command=load_signature_file).pack(side=tk.LEFT, padx=5)

text_verify_sig = scrolledtext.ScrolledText(verify_tab, height=4)
text_verify_sig.pack(fill=tk.BOTH, expand=True, padx=10)

tk.Button(verify_tab, text="Verify", width=16, command=verify_ui).pack(pady=5)

root.mainloop()
