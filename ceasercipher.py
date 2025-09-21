import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import random
import string

# ===================== Helper Functions =====================

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def is_base64(s):
    try:
        base64.b64decode(s)
        return True
    except Exception:
        return False

def generate_codename():
    adjectives = ["Shadow", "Silent", "Crimson", "Phantom", "Stealth", "Midnight", "Ghost"]
    nouns = ["Falcon", "Tiger", "Viper", "Hawk", "Wolf", "Eagle", "Panther"]
    return random.choice(adjectives) + "-" + random.choice(nouns) + "-" + ''.join(random.choices(string.digits, k=3))

def encrypt_text(text):
    key = key_entry.get()
    if len(key) not in [16, 24, 32]:
        messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long")
        return ""
    iv = get_random_bytes(16)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(text).encode('utf-8'))
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def decrypt_text(text):
    try:
        key = key_entry.get()
        data = base64.b64decode(text)
        if len(key) not in [16, 24, 32]:
            messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long")
            return ""
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct).decode('utf-8').rstrip()
        return pt
    except Exception:
        messagebox.showerror("Error", "Failed to decrypt. Check key or input.")
        return ""

def display_result(msg, codename=""):
    banner = "*" * 60 + "\n"
    header = f"🕵️ MISSION CODE: {codename} 🕵️\n" if codename else ""
    full_msg = banner + header + msg + "\n" + banner
    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, full_msg)
    mission_log_dict[codename] = msg
    mission_log.insert(tk.END, codename)

def auto_process():
    text = input_box.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Warning", "No input found!")
        return
    codename = generate_codename()
    if is_base64(text):
        pt = decrypt_text(text)
        display_result(f"🔓 DECRYPTED MISSION 🔓\n{pt}", codename)
    else:
        ct = encrypt_text(text)
        display_result(f"🔒 TOP SECRET ENCRYPTED MISSION 🔒\n{ct}", codename)

def copy_to_clipboard():
    output = result_box.get("1.0", tk.END).strip()
    if output:
        root.clipboard_clear()
        root.clipboard_append(output)
        root.update()
        messagebox.showinfo("Copied", "Mission copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No result to copy!")

def clear_all():
    input_box.delete("1.0", tk.END)
    key_entry.delete(0, tk.END)
    result_box.delete("1.0", tk.END)
    mission_log.delete(0, tk.END)
    mission_log_dict.clear()

def toggle_key_visibility():
    if key_entry.cget("show") == "*":
        key_entry.config(show="")
        toggle_btn.config(text="Hide Key")
    else:
        key_entry.config(show="*")
        toggle_btn.config(text="Show Key")

def save_to_file():
    output = result_box.get("1.0", tk.END).strip()
    if not output:
        messagebox.showwarning("Warning", "No result to save!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files","*.txt"),("All Files","*.*")])
    if file_path:
        with open(file_path, "w") as f:
            f.write(output)
        messagebox.showinfo("Saved", f"Mission saved to {file_path}")

def load_from_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files","*.txt"),("All Files","*.*")])
    if file_path:
        with open(file_path, "r") as f:
            content = f.read()
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, content)
        messagebox.showinfo("Loaded", f"Mission loaded from {file_path}")

def random_mission():
    missions = [
        "Meet at the hidden base at midnight!",
        "Retrieve secret documents from safe house 42.",
        "Agent X rendezvous at abandoned warehouse.",
        "Mission starts at dawn, avoid enemy patrols.",
        "Top secret files are stored in the vault under HQ."
    ]
    text = random.choice(missions)
    input_box.delete("1.0", tk.END)
    input_box.insert(tk.END, text)
    messagebox.showinfo("Mission Generated", "Random spy mission loaded!")

def load_mission_from_log(event):
    selection = mission_log.curselection()
    if selection:
        index = selection[0]
        codename = mission_log.get(index)
        msg = mission_log_dict.get(codename, "")
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, msg)

def export_mission_log():
    if not mission_log_dict:
        messagebox.showwarning("Warning", "No missions in the log to export!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files","*.txt"),("All Files","*.*")])
    if file_path:
        with open(file_path, "w") as f:
            for codename, message in mission_log_dict.items():
                banner = "*" * 60 + "\n"
                f.write(f"{banner}MISSION CODE: {codename}\n{message}\n{banner}\n\n")
        messagebox.showinfo("Exported", f"Mission Log exported to {file_path}")

# ===================== Theme Switcher =====================
current_theme = "dark"

def switch_theme():
    global current_theme
    if current_theme == "dark":
        # Light Theme Colors
        bg_color = "white"
        fg_color = "black"
        btn_bg = "#CCCCCC"
        btn_fg = "black"
        text_bg = "white"
        text_fg = "black"
        current_theme = "light"
    else:
        # Dark Spy Theme
        bg_color = "#0B0B45"
        fg_color = "white"
        btn_bg = "#2B2B7A"
        btn_fg = "white"
        text_bg = "#1A1A3F"
        text_fg = "white"
        current_theme = "dark"
    
    # Change root background
    root.configure(bg=bg_color)
    
    # Update all frames and widgets
    for widget in root.winfo_children():
        if isinstance(widget, tk.LabelFrame) or isinstance(widget, tk.Frame):
            widget.configure(bg=bg_color, fg=fg_color)
        for child in widget.winfo_children():
            if isinstance(child, tk.Label):
                child.configure(bg=bg_color, fg=fg_color)
            elif isinstance(child, tk.Button):
                child.configure(bg=btn_bg, fg=btn_fg)
            elif isinstance(child, tk.Text) or isinstance(child, scrolledtext.ScrolledText):
                child.configure(bg=text_bg, fg=text_fg)
            elif isinstance(child, tk.Entry):
                child.configure(bg=text_bg, fg=text_fg)
            elif isinstance(child, tk.Listbox):
                child.configure(bg=text_bg, fg=text_fg)
            elif isinstance(child, tk.Scrollbar):
                child.configure(bg=bg_color)

# ===================== GUI =====================
root = tk.Tk()
root.title("🕵️ Ultimate Spy AES-CBC Encryption App 🕵️")
root.configure(bg="#0B0B45")

# Frames for neat layout
input_frame = tk.LabelFrame(root, text="Input / Plaintext / Ciphertext", bg="#0B0B45", fg="white", padx=5, pady=5)
input_frame.pack(padx=10, pady=5, fill="x")
input_box = tk.Text(input_frame, width=70, height=4, bg="#1A1A3F", fg="white")
input_box.pack()

key_frame = tk.Frame(root, bg="#0B0B45")
key_frame.pack(padx=10, pady=5, fill="x")
tk.Label(key_frame, text="Key (16/24/32 chars):", bg="#0B0B45", fg="white").pack(side=tk.LEFT)
key_entry = tk.Entry(key_frame, width=40, show="*", bg="#1A1A3F", fg="white")
key_entry.pack(side=tk.LEFT, padx=5)
toggle_btn = tk.Button(key_frame, text="Show Key", command=toggle_key_visibility, bg="#2B2B7A", fg="white")
toggle_btn.pack(side=tk.LEFT)

# Buttons
btn_frame = tk.Frame(root, bg="#0B0B45")
btn_frame.pack(padx=10, pady=5)
tk.Button(btn_frame, text="Auto Encrypt/Decrypt", command=auto_process, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Random Mission", command=random_mission, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Copy Result", command=copy_to_clipboard, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Clear All", command=clear_all, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Save Result", command=save_to_file, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Load Text", command=load_from_file, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Export Mission Log", command=export_mission_log, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Switch Theme", command=switch_theme, bg="#2B2B7A", fg="white").pack(side=tk.LEFT, padx=5)

# Output
output_frame = tk.LabelFrame(root, text="Mission Output", bg="#0B0B45", fg="white", padx=5, pady=5)
output_frame.pack(padx=10, pady=5, fill="x")
result_box = scrolledtext.ScrolledText(output_frame, width=70, height=6, bg="#1A1A3F", fg="white")
result_box.pack()

# Mission Log
log_frame = tk.LabelFrame(root, text="📝 Mission Log", bg="#0B0B45", fg="white", padx=5, pady=5)
log_frame.pack(padx=10, pady=5, fill="both", expand=True)
mission_log = tk.Listbox(log_frame, width=70, height=6, bg="#1A1A3F", fg="white")
mission_log.pack(side=tk.LEFT, fill="both", expand=True)
scrollbar = tk.Scrollbar(log_frame)
scrollbar.pack(side=tk.RIGHT, fill="y")
mission_log.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=mission_log.yview)
mission_log.bind("<Double-1>", load_mission_from_log)

# Dictionary to store full messages for log
mission_log_dict = {}

root.mainloop()
