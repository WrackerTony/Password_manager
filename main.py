import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from cryptography.fernet import Fernet
import bcrypt
import base64
import os
from datetime import datetime
import re

class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Encryption key
        self.key = None
        self.fernet = None
        self.current_user = None
        
        # Initialize database
        self.init_database()
        
        # Start with login frame
        self.show_login_frame()
        
    def init_database(self):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Create users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT PRIMARY KEY, password TEXT, salt TEXT)''')
        
        # Create passwords table
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                    (id INTEGER PRIMARY KEY, username TEXT,
                     site TEXT, site_username TEXT, password TEXT,
                     FOREIGN KEY (username) REFERENCES users(username))''')
        
        conn.commit()
        conn.close()

    def show_login_frame(self):
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create login frame
        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Login elements
        ttk.Label(login_frame, text="Password Manager Login", font=('Helvetica', 16)).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(login_frame, text="Username:").grid(row=1, column=0, pady=5)
        username = ttk.Entry(login_frame, width=30)
        username.grid(row=1, column=1, pady=5)
        
        ttk.Label(login_frame, text="Password:").grid(row=2, column=0, pady=5)
        # Removed show="*" from password entry
        password = ttk.Entry(login_frame, width=30, show="*")
        password.grid(row=2, column=1, pady=5)
        
        ttk.Button(login_frame, text="Login", command=lambda: self.login(username.get(), password.get())).grid(row=3, column=0, columnspan=2, pady=20)
        ttk.Button(login_frame, text="Register", command=self.show_register_frame).grid(row=4, column=0, columnspan=2)

    def show_register_frame(self):
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create register frame
        register_frame = ttk.Frame(self.root, padding="20")
        register_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(register_frame, text="Register New Account", font=('Helvetica', 16)).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(register_frame, text="Username:").grid(row=1, column=0, pady=5)
        username = ttk.Entry(register_frame, width=30)
        username.grid(row=1, column=1, pady=5)
        
        ttk.Label(register_frame, text="Password:").grid(row=2, column=0, pady=5)
        # Removed show="*" from password entry
        password = ttk.Entry(register_frame, width=30, show="*")
        password.grid(row=2, column=1, pady=5)
        
        ttk.Label(register_frame, text="Confirm Password:").grid(row=3, column=0, pady=5)
        # Removed show="*" from confirm password entry
        confirm_password = ttk.Entry(register_frame, width=30, show="*")
        confirm_password.grid(row=3, column=1, pady=5)
        
        ttk.Button(register_frame, text="Register", 
                  command=lambda: self.register(username.get(), password.get(), confirm_password.get())
                  ).grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(register_frame, text="Back to Login", 
                  command=self.show_login_frame
                  ).grid(row=5, column=0, columnspan=2)

    def show_main_frame(self):
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create password list
        self.password_tree = ttk.Treeview(main_frame, columns=('Site', 'Username', 'Password'), show='headings')
        self.password_tree.heading('Site', text='Site')
        self.password_tree.heading('Username', text='Username')
        self.password_tree.heading('Password', text='Password')
        self.password_tree.grid(row=0, column=0, columnspan=3, pady=20)
        
        # Add password section
        ttk.Label(main_frame, text="Add New Password", font=('Helvetica', 12)).grid(row=1, column=0, columnspan=3, pady=10)
        
        ttk.Label(main_frame, text="Site:").grid(row=2, column=0)
        site_entry = ttk.Entry(main_frame)
        site_entry.grid(row=2, column=1)
        
        ttk.Label(main_frame, text="Username:").grid(row=3, column=0)
        username_entry = ttk.Entry(main_frame)
        username_entry.grid(row=3, column=1)
        
        ttk.Label(main_frame, text="Password:").grid(row=4, column=0)
        # Removed show="*" from password entry
        password_entry = ttk.Entry(main_frame, show="*")
        password_entry.grid(row=4, column=1)
        
        # Buttons
        ttk.Button(main_frame, text="Add Password",
                  command=lambda: self.add_password(site_entry.get(), username_entry.get(), password_entry.get())
                  ).grid(row=5, column=0, pady=10)
        
        ttk.Button(main_frame, text="Delete Selected",
                  command=self.delete_password
                  ).grid(row=5, column=1, pady=10)
        
        ttk.Button(main_frame, text="Logout",
                  command=self.logout
                  ).grid(row=5, column=2, pady=10)
        
        # Load existing passwords
        self.load_passwords()

    def load_passwords(self):
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
            
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute("SELECT site, site_username, password FROM passwords WHERE username=?", (self.current_user,))
        passwords = c.fetchall()
        
        # Convert to list and sort by site name (case-insensitive)
        passwords = sorted(passwords, key=lambda x: x[0].lower())
        
        for site, username, encrypted_password in passwords:
            decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
            self.password_tree.insert('', 'end', values=(site, username, decrypted_password))
                
        conn.close()


    # Rest of the methods remain unchanged
    def login(self, username, password):
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute("SELECT password, salt FROM users WHERE username=?", (username,))
        result = c.fetchone()
        
        if result:
            stored_password, salt = result
            salt = salt.encode('utf-8')
            
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                self.current_user = username
                self.key = base64.urlsafe_b64encode(bcrypt.kdf(
                    password.encode('utf-8'),
                    salt,
                    desired_key_bytes=32,
                    rounds=100
                ))
                self.fernet = Fernet(self.key)
                self.show_main_frame()
            else:
                messagebox.showerror("Error", "Invalid username or password")
        else:
            messagebox.showerror("Error", "Invalid username or password")
            
        conn.close()

    def register(self, username, password, confirm_password):
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return
            
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        c.execute("SELECT username FROM users WHERE username=?", (username,))
        if c.fetchone():
            messagebox.showerror("Error", "Username already exists")
            conn.close()
            return
            
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        try:
            c.execute("INSERT INTO users VALUES (?, ?, ?)", 
                     (username, hashed.decode('utf-8'), salt.decode('utf-8')))
            conn.commit()
            messagebox.showinfo("Success", "Registration successful")
            self.show_login_frame()
        except:
            messagebox.showerror("Error", "Registration failed")
            
        conn.close()

    def add_password(self, site, username, password):
        if not site or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        encrypted_password = self.fernet.encrypt(password.encode()).decode()
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO passwords (username, site, site_username, password) VALUES (?, ?, ?, ?)",
                     (self.current_user, site, username, encrypted_password))
            conn.commit()
            messagebox.showinfo("Success", "Password added successfully")
            self.load_passwords()
        except:
            messagebox.showerror("Error", "Failed to add password")
            
        conn.close()

    def delete_password(self):
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a password to delete")
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this password?"):
            item = self.password_tree.item(selected[0])
            site = item['values'][0]
            username = item['values'][1]
            
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            
            try:
                c.execute("DELETE FROM passwords WHERE username=? AND site=? AND site_username=?",
                         (self.current_user, site, username))
                conn.commit()
                messagebox.showinfo("Success", "Password deleted successfully")
                self.load_passwords()
            except:
                messagebox.showerror("Error", "Failed to delete password")
                
            conn.close()

    def logout(self):
        self.current_user = None
        self.key = None
        self.fernet = None
        self.show_login_frame()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()
