import tkinter as tk
from tkinter import ttk, messagebox
import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class MeowPassManager:
    def __init__(self, root):
        self.root = root
        self.root.title("🐱 MeowPass")
        self.root.geometry("400x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#FFD1DC")  # Pink background

        # Load or create device-level master key on first run
        self.master_key_path = os.path.expanduser("~/.meowpass_master_key")
        if os.path.exists(self.master_key_path):
            with open(self.master_key_path, "r") as f:
                self.device_master_key = f.read().strip()
            messagebox.showinfo("Welcome Back", "🐾 Welcome back to MeowPass!")
        else:
            top = tk.Toplevel(self.root)
            top.title("Create Master Key")
            top.geometry("300x150")
            top.configure(bg="#FFD1DC")

            ttk.Label(top, text="Create Master Key:").pack(pady=10)
            entry = ttk.Entry(top, show="*")
            entry.pack()

            def save_device_key():
                val = entry.get()
                if val:
                    with open(self.master_key_path, "w") as f:
                        f.write(val.strip())
                    self.device_master_key = val.strip()
                    top.destroy()
                    messagebox.showinfo("Welcome", "🎉 Welcome to MeowPass! Your master key is now set.")

            ttk.Button(top, text="Save", command=save_device_key).pack(pady=10)
            self.root.wait_window(top)
        
        # Custom window icon (comment out if you don't have an icon)
        try:
            self.root.iconbitmap("cat_icon.ico")  # Replace with your icon file
        except:
            pass
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#FFD1DC")
        self.style.configure("TLabel", background="#FFD1DC", font=("Comic Sans MS", 10))
        self.style.configure("TButton", font=("Comic Sans MS", 10), padding=5)
        self.style.configure("Bold.TLabel", font=("Comic Sans MS", 10, "bold"))
        
        # Main container
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        # Header with cat animation
        self.header = ttk.Frame(self.main_frame)
        self.header.pack(fill=tk.X)
        
        self.cat_label = ttk.Label(
            self.header, 
            text="(≧◡≦) MeowPass", 
            font=("Comic Sans MS", 16, "bold"),
            foreground="#FF1493"
        )
        self.cat_label.pack()
        
        # Tab control
        self.tab_control = ttk.Notebook(self.main_frame)
        self.tab1 = ttk.Frame(self.tab_control)
        self.tab2 = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab1, text="🔑 Vault")
        self.tab_control.add(self.tab2, text="🐾 Generator")

        self.tab3 = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab3, text="📖 Help")
        self.create_help_tab()

        self.tab_control.pack(expand=1, fill="both")
        
        # Initialize tabs
        self.create_vault_tab()
        self.create_generator_tab()
        
        # Initialize password storage
        self.passwords = {}
        self.load_vault()
        self.master_key = None
        
        # Animation cycle
        self.cat_faces = ["(≧◡≦)", "(=｀ω´=)", "(=^･ω･^=)", "(=^‥^=)", "(=ＴェＴ=)"]
        self.animate_cat()
    
    def save_vault(self):
        """Save the password vault to disk as JSON"""
        vault_path = os.path.expanduser("~/.meowpass_vault.json")
        try:
            with open(vault_path, "w") as f:
                json.dump(self.passwords, f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault: {e}")

    def load_vault(self):
        """Load the password vault from disk"""
        vault_path = os.path.expanduser("~/.meowpass_vault.json")
        if os.path.exists(vault_path):
            try:
                with open(vault_path, "r") as f:
                    self.passwords = json.load(f)
                self.update_password_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load vault: {e}")

    def animate_cat(self):
        """Cycle through cat faces for animation"""
        current_face = self.cat_label.cget("text").split(" ")[0]
        next_face = self.cat_faces[(self.cat_faces.index(current_face) + 1) % len(self.cat_faces)]
        self.cat_label.config(text=f"{next_face} MeowPass")
        self.root.after(1000, self.animate_cat)
    
    def create_vault_tab(self):
        """Password vault tab"""
        # Master key setup
        ttk.Label(self.tab1, text="Master Key:", style="Bold.TLabel").pack(pady=(10, 0))
        self.master_key_entry = ttk.Entry(self.tab1, show="*")
        self.master_key_entry.pack()
        
        # Password list
        self.pass_list = tk.Listbox(
            self.tab1, 
            height=10,
            selectbackground="#FF69B4",
            selectforeground="white",
            font=("Comic Sans MS", 9)
        )
        self.pass_list.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Action buttons
        btn_frame = ttk.Frame(self.tab1)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Add", command=self.add_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="View", command=self.view_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Delete", command=self.delete_password).pack(side=tk.LEFT, padx=2)
    
    def create_generator_tab(self):
        """Password generator tab"""
        ttk.Label(self.tab2, text="Password Length:", style="Bold.TLabel").pack(pady=(10, 0))
        self.length_var = tk.IntVar(value=12)
        ttk.Spinbox(self.tab2, from_=8, to=32, textvariable=self.length_var).pack()
        
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            self.tab2, 
            text="Include Special Characters", 
            variable=self.special_var
        ).pack(pady=5)
        
        ttk.Button(
            self.tab2, 
            text="Generate Password", 
            command=self.generate_password
        ).pack(pady=10)
        
        self.gen_pass_var = tk.StringVar()
        ttk.Entry(
            self.tab2, 
            textvariable=self.gen_pass_var,
            font=("Courier New", 12),
            state="readonly"
        ).pack(fill=tk.X, padx=10)
        
        ttk.Button(
            self.tab2, 
            text="Copy to Clipboard", 
            command=self.copy_to_clipboard
        ).pack(pady=5)
    
    # Vault functions
    def add_password(self):
        """Add a new password to the vault"""
        if not self.master_key_entry.get():
            messagebox.showerror("Error", "Please set a master key first!")
            return
            
        top = tk.Toplevel(self.root)
        top.title("Add Password")
        top.geometry("300x200")
        top.configure(bg="#FFD1DC")
        
        ttk.Label(top, text="Service/Website:").pack(pady=(10, 0))
        service_entry = ttk.Entry(top)
        service_entry.pack()
        
        ttk.Label(top, text="Username:").pack(pady=(5, 0))
        user_entry = ttk.Entry(top)
        user_entry.pack()
        
        ttk.Label(top, text="Password:").pack(pady=(5, 0))
        pass_entry = ttk.Entry(top, show="*")
        pass_entry.pack()
        
        def save_password():
            service = service_entry.get()
            username = user_entry.get()
            password = pass_entry.get()
            
            if service and username and password:
                encrypted = self.encrypt_password(password)
                self.passwords[service] = {
                    "username": username,
                    "password": encrypted
                }
                self.update_password_list()
                self.save_vault()
                top.destroy()
        
        ttk.Button(top, text="Save", command=save_password).pack(pady=10)
    
    def view_password(self):
        """View selected password"""
        selection = self.pass_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password first!")
            return
            
        service = self.pass_list.get(selection[0])
        if not self.master_key_entry.get():
            messagebox.showerror("Error", "Master key required to view passwords!")
            return
            
        password = self.decrypt_password(self.passwords[service]["password"])
        
        top = tk.Toplevel(self.root)
        top.title(f"Password for {service}")
        top.geometry("300x150")
        top.configure(bg="#FFD1DC")
        
        ttk.Label(top, text=f"Service: {service}").pack(pady=(10, 0))
        ttk.Label(top, text=f"Username: {self.passwords[service]['username']}").pack()
        ttk.Label(top, text="Password:").pack(pady=(5, 0))
        
        pass_var = tk.StringVar(value=password)
        ttk.Entry(top, textvariable=pass_var, show="*", state="readonly").pack()
        
        def copy_password():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        
        ttk.Button(top, text="Copy Password", command=copy_password).pack(pady=10)
    
    def delete_password(self):
        """Delete selected password"""
        selection = self.pass_list.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password first!")
            return
            
        service = self.pass_list.get(selection[0])
        if messagebox.askyesno("Confirm", f"Delete password for {service}?"):
            del self.passwords[service]
            self.update_password_list()
            self.save_vault()
    
    def update_password_list(self):
        """Refresh the password list display"""
        self.pass_list.delete(0, tk.END)
        for service in sorted(self.passwords.keys()):
            self.pass_list.insert(tk.END, service)
    
    def encrypt_password(self, password):
        """Encrypt a password with the master key and return salt + encrypted data"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key_entry.get().encode()))
        f = Fernet(key)
        encrypted = f.encrypt(password.encode())
        # Store salt + encrypted data together, base64-encoded
        return base64.urlsafe_b64encode(salt + encrypted).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt a password using the master key and embedded salt"""
        decoded = base64.urlsafe_b64decode(encrypted_password.encode())
        salt = decoded[:16]
        encrypted = decoded[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key_entry.get().encode()))
        f = Fernet(key)
        return f.decrypt(encrypted).decode()
    
    # Generator functions
    def generate_password(self):
        """Generate a random password with hyphens after every 3 characters"""
        import random
        import string

        length = self.length_var.get()
        chars = string.ascii_letters + string.digits
        if self.special_var.get():
            chars += "!@#$%^&*()"

        raw_password = ''.join(random.choice(chars) for _ in range(length))

        if length <= 3:
            password = raw_password
        else:
            grouped = [raw_password[i:i+3] for i in range(0, len(raw_password), 3)]
            password = '-'.join(grouped)

        self.gen_pass_var.set(password)
    
    def copy_to_clipboard(self):
        """Copy generated password to clipboard"""
        if self.gen_pass_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.gen_pass_var.get())
            messagebox.showinfo("Copied", "Password copied to clipboard!")
    
    def create_help_tab(self):
        """Help tab with usage instructions"""
        instructions = [
            "💡 Welcome to MeowPass!",
            "",
            "🔐 To use the Vault tab:",
            "  1. Enter your master key.",
            "  2. Click 'Add' to store a new password.",
            "  3. Select a service and click 'View' to reveal it.",
            "  4. Click 'Delete' to remove a saved password.",
            "",
            "🔧 In the Generator tab:",
            "  1. Choose a length and whether to include symbols.",
            "  2. Click 'Generate Password'.",
            "  3. Copy it to your clipboard with one click.",
            "",
            "🐱 Your data is encrypted locally using your master key.",
            "  Do not forget your master key! MeowPass cannot recover it.",
        ]

        text_widget = tk.Text(self.tab3, wrap="word", font=("Comic Sans MS", 10), bg="#FFF0F5")
        text_widget.insert("1.0", "\n".join(instructions))
        text_widget.config(state="disabled")
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = MeowPassManager(root)
    root.mainloop()