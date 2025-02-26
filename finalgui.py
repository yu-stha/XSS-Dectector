#!/usr/bin/env python3
"""
XSS Vulnerability Scanner GUI - A tool to detect XSS vulnerabilities in web forms
with user authentication and scan history.
"""

import os
import platform
import threading
import datetime
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import mysql.connector
import colorama
import requests

# Initialize colorama
colorama.init()

# XSS payloads for testing
xss_payloads = [
    "<script>alert('XSS');</script>",
    "<img src='x' onerror='alert(\"XSS\")'>",
    "<img src=1 href=1 onerror='javascript:alert(1)'></img>",
    "<audio src=1 href=1 onerror='javascript:alert(1)'></audio>",
    "<video src=1 href=1 onerror='javascript:alert(1)'></video>"
    # Add more payloads as needed
]

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'xss'
}

class Database:
    def __init__(self):
        self.connection = None
        self.initialize_database()
        
    def connect(self):
        try:
            self.connection = mysql.connector.connect(**DB_CONFIG)
            return self.connection
        except mysql.connector.Error as err:
            messagebox.showerror("Database Error", f"Error connecting to database: {err}")
            return None
            
    def initialize_database(self):
        try:
            # Connect to MySQL server
            connection = mysql.connector.connect(
                host=DB_CONFIG['host'],
                user=DB_CONFIG['user'],
                password=DB_CONFIG['password']
            )
            
            cursor = connection.cursor()
            
            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
            cursor.execute(f"USE {DB_CONFIG['database']}")
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create scan_history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    url VARCHAR(255) NOT NULL,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    vulnerability_found BOOLEAN DEFAULT FALSE,
                    form_details TEXT,
                    payload_used TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            connection.commit()
            cursor.close()
            connection.close()
            
            print("Database initialized successfully")
        except mysql.connector.Error as err:
            print(f"Error initializing database: {err}")
    
    def register_user(self, username, password):
        """Register a new user in the database."""
        connection = self.connect()
        if not connection:
            return False
            
        cursor = connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, password)
            )
            connection.commit()
            return True
        except mysql.connector.Error as err:
            print(f"Error registering user: {err}")
            return False
        finally:
            cursor.close()
            connection.close()
    
    def login_user(self, username, password):
        """Authenticate a user."""
        connection = self.connect()
        if not connection:
            return None
            
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT id, username FROM users WHERE username = %s AND password = %s",
                (username, password)
            )
            user = cursor.fetchone()
            return user
        except mysql.connector.Error as err:
            print(f"Error logging in: {err}")
            return None
        finally:
            cursor.close()
            connection.close()
    
    def save_scan_result(self, user_id, url, vulnerability_found, form_details, payload_used):
        """Save scan results to history."""
        connection = self.connect()
        if not connection:
            return False
            
        cursor = connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO scan_history 
                (user_id, url, vulnerability_found, form_details, payload_used) 
                VALUES (%s, %s, %s, %s, %s)""",
                (user_id, url, vulnerability_found, form_details, payload_used)
            )
            connection.commit()
            return True
        except mysql.connector.Error as err:
            print(f"Error saving scan result: {err}")
            return False
        finally:
            cursor.close()
            connection.close()
    
    def get_user_scan_history(self, user_id):
        """Retrieve scan history for a user."""
        connection = self.connect()
        if not connection:
            return []
            
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """SELECT id, url, scan_date, vulnerability_found, form_details, payload_used 
                FROM scan_history 
                WHERE user_id = %s 
                ORDER BY scan_date DESC""",
                (user_id,)
            )
            history = cursor.fetchall()
            return history
        except mysql.connector.Error as err:
            print(f"Error retrieving scan history: {err}")
            return []
        finally:
            cursor.close()
            connection.close()


# XSS Scanner functions
def get_all_forms(url):
    """Extract all forms from the URL."""
    try:
        soup = bs(requests.get(url).content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException:
        return []

def get_form_details(form):
    """Extract form details including action, method and inputs."""
    details = {}
    # Get the form action (target URL)
    action = form.attrs.get("action", "")
    
    # Get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    
    # Get all form inputs
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """Submit the form with the given payload value."""
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input_name = input.get("name")
            if input_name:
                data[input_name] = value
    
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    return requests.get(target_url, params=data)


class XSSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("XSS Vulnerability Scanner")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        
        self.db = Database()
        self.current_user = None
        
        # Create frames for all pages
        self.welcome_frame = ttk.Frame(root)
        self.login_frame = ttk.Frame(root)
        self.register_frame = ttk.Frame(root)
        self.scanner_frame = ttk.Frame(root)
        self.history_frame = ttk.Frame(root)
        
        # Initialize UI components for each page
        self.init_welcome_ui()
        self.init_login_ui()
        self.init_register_ui()
        self.init_scanner_ui()
        self.init_history_ui()
        
        # Show welcome page initially
        self.show_welcome_page()
        
    def init_welcome_ui(self):
        """Initialize the welcome page UI."""
        welcome_container = ttk.Frame(self.welcome_frame)
        welcome_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)
        
        # Welcome message
        ttk.Label(
            welcome_container, 
            text="XSS Vulnerability Scanner", 
            font=("Helvetica", 20, "bold")
        ).pack(pady=30)
        
        ttk.Label(
            welcome_container,
            text="A tool to detect Cross-Site Scripting vulnerabilities in web applications",
            font=("Helvetica", 12)
        ).pack(pady=10)
        
        # Button container
        btn_frame = ttk.Frame(welcome_container)
        btn_frame.pack(pady=50)
        
        # Login button
        login_btn = ttk.Button(
            btn_frame, 
            text="Login", 
            command=self.show_login_page,
            width=20
        )
        login_btn.grid(row=0, column=0, padx=20, pady=10)
        
        # Register button
        register_btn = ttk.Button(
            btn_frame, 
            text="Register", 
            command=self.show_register_page,
            width=20
        )
        register_btn.grid(row=1, column=0, padx=20, pady=10)
        
    def init_login_ui(self):
        """Initialize the login page UI."""
        login_container = ttk.Frame(self.login_frame)
        login_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)
        
        # Title
        ttk.Label(
            login_container, 
            text="Login", 
            font=("Helvetica", 16, "bold")
        ).pack(pady=30)
        
        # Form frame
        form_frame = ttk.Frame(login_container)
        form_frame.pack(pady=20)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.login_username = ttk.Entry(form_frame, width=30)
        self.login_username.grid(row=0, column=1, padx=10, pady=10)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.login_password = ttk.Entry(form_frame, width=30, show="*")
        self.login_password.grid(row=1, column=1, padx=10, pady=10)
        
        # Button frame
        btn_frame = ttk.Frame(login_container)
        btn_frame.pack(pady=30)
        
        # Login button
        login_btn = ttk.Button(btn_frame, text="Login", command=self.login, width=15)
        login_btn.grid(row=0, column=0, padx=10, pady=10)
        
        # Back button
        back_btn = ttk.Button(btn_frame, text="Back", command=self.show_welcome_page, width=15)
        back_btn.grid(row=0, column=1, padx=10, pady=10)
        
        # Register link
        register_frame = ttk.Frame(login_container)
        register_frame.pack(pady=20)
        
        ttk.Label(register_frame, text="Don't have an account?").pack(side=tk.LEFT, padx=(0, 5))
        register_link = ttk.Label(register_frame, text="Register here", foreground="blue", cursor="hand2")
        register_link.pack(side=tk.LEFT)
        register_link.bind("<Button-1>", lambda e: self.show_register_page())
        
    def init_register_ui(self):
        """Initialize the registration page UI."""
        register_container = ttk.Frame(self.register_frame)
        register_container.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)
        
        # Title
        ttk.Label(
            register_container, 
            text="Register", 
            font=("Helvetica", 16, "bold")
        ).pack(pady=30)
        
        # Form frame
        form_frame = ttk.Frame(register_container)
        form_frame.pack(pady=20)
        
        # Username
        ttk.Label(form_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.reg_username = ttk.Entry(form_frame, width=30)
        self.reg_username.grid(row=0, column=1, padx=10, pady=10)
        
        # Password
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.reg_password = ttk.Entry(form_frame, width=30, show="*")
        self.reg_password.grid(row=1, column=1, padx=10, pady=10)
        
        # Confirm Password
        ttk.Label(form_frame, text="Confirm Password:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        self.reg_confirm_password = ttk.Entry(form_frame, width=30, show="*")
        self.reg_confirm_password.grid(row=2, column=1, padx=10, pady=10)
        
        # Button frame
        btn_frame = ttk.Frame(register_container)
        btn_frame.pack(pady=30)
        
        # Register button
        register_btn = ttk.Button(btn_frame, text="Register", command=self.register, width=15)
        register_btn.grid(row=0, column=0, padx=10, pady=10)
        
        # Back button
        back_btn = ttk.Button(btn_frame, text="Back", command=self.show_welcome_page, width=15)
        back_btn.grid(row=0, column=1, padx=10, pady=10)
        
        # Login link
        login_frame = ttk.Frame(register_container)
        login_frame.pack(pady=20)
        
        ttk.Label(login_frame, text="Already have an account?").pack(side=tk.LEFT, padx=(0, 5))
        login_link = ttk.Label(login_frame, text="Login here", foreground="blue", cursor="hand2")
        login_link.pack(side=tk.LEFT)
        login_link.bind("<Button-1>", lambda e: self.show_login_page())
        
    def init_scanner_ui(self):
        """Initialize the scanner page UI."""
        scanner_container = ttk.Frame(self.scanner_frame)
        scanner_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header with user info and navigation
        header_frame = ttk.Frame(scanner_container)
        header_frame.pack(fill=tk.X, pady=10)
        
        self.user_label = ttk.Label(header_frame, text="", font=("Helvetica", 12))
        self.user_label.pack(side=tk.LEFT)
        
        nav_frame = ttk.Frame(header_frame)
        nav_frame.pack(side=tk.RIGHT)
        
        history_btn = ttk.Button(nav_frame, text="History", command=self.show_history_page)
        history_btn.pack(side=tk.LEFT, padx=5)
        
        logout_btn = ttk.Button(nav_frame, text="Logout", command=self.logout)
        logout_btn.pack(side=tk.LEFT, padx=5)
        
        # URL input
        url_frame = ttk.Frame(scanner_container)
        url_frame.pack(fill=tk.X, pady=20)
        
        ttk.Label(url_frame, text="Target URL:").pack(side=tk.LEFT, padx=(0, 10))
        self.url_entry = ttk.Entry(url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        scan_btn = ttk.Button(url_frame, text="Scan", command=self.start_scan)
        scan_btn.pack(side=tk.LEFT, padx=10)
        
        # Results display
        result_frame = ttk.LabelFrame(scanner_container, text="Scan Results")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
    def init_history_ui(self):
        """Initialize the history page UI."""
        history_container = ttk.Frame(self.history_frame)
        history_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header with user info and navigation
        header_frame = ttk.Frame(history_container)
        header_frame.pack(fill=tk.X, pady=10)
        
        self.history_user_label = ttk.Label(header_frame, text="", font=("Helvetica", 12))
        self.history_user_label.pack(side=tk.LEFT)
        
        nav_frame = ttk.Frame(header_frame)
        nav_frame.pack(side=tk.RIGHT)
        
        scanner_btn = ttk.Button(nav_frame, text="Scanner", command=self.show_scanner_page)
        scanner_btn.pack(side=tk.LEFT, padx=5)
        
        logout_btn = ttk.Button(nav_frame, text="Logout", command=self.logout)
        logout_btn.pack(side=tk.LEFT, padx=5)
        
        # Title
        ttk.Label(history_container, text="Scan History", font=("Helvetica", 14, "bold")).pack(pady=10)
        
        # Treeview frame
        tree_frame = ttk.Frame(history_container)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for scan history
        columns = ("id", "url", "date", "status", "details")
        self.history_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        # Define headings
        self.history_tree.heading("id", text="ID")
        self.history_tree.heading("url", text="URL")
        self.history_tree.heading("date", text="Scan Date")
        self.history_tree.heading("status", text="Vulnerability")
        self.history_tree.heading("details", text="Details")
        
        # Define columns
        self.history_tree.column("id", width=50)
        self.history_tree.column("url", width=200)
        self.history_tree.column("date", width=150)
        self.history_tree.column("status", width=100)
        self.history_tree.column("details", width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scrollbar.set)
        
        # Pack elements
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button frame
        btn_frame = ttk.Frame(history_container)
        btn_frame.pack(fill=tk.X, pady=10)
        
        view_details_btn = ttk.Button(btn_frame, text="View Details", command=self.view_scan_details)
        view_details_btn.pack(side=tk.LEFT, padx=5)
        
        refresh_btn = ttk.Button(btn_frame, text="Refresh", command=self.load_history)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
    # Page navigation methods
    def show_welcome_page(self):
        """Show the welcome page."""
        self.hide_all_frames()
        self.welcome_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_login_page(self):
        """Show the login page."""
        self.hide_all_frames()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_register_page(self):
        """Show the registration page."""
        self.hide_all_frames()
        self.register_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_scanner_page(self):
        """Show the scanner page."""
        if not self.current_user:
            messagebox.showerror("Error", "You must be logged in to access the scanner")
            self.show_login_page()
            return
            
        self.hide_all_frames()
        self.user_label.config(text=f"Logged in as: {self.current_user['username']}")
        self.scanner_frame.pack(fill=tk.BOTH, expand=True)
        
    def show_history_page(self):
        """Show the history page."""
        if not self.current_user:
            messagebox.showerror("Error", "You must be logged in to access the history")
            self.show_login_page()
            return
            
        self.hide_all_frames()
        self.history_user_label.config(text=f"Logged in as: {self.current_user['username']}")
        self.history_frame.pack(fill=tk.BOTH, expand=True)
        self.load_history()
        
    def hide_all_frames(self):
        """Hide all page frames."""
        for frame in [self.welcome_frame, self.login_frame, self.register_frame, 
                     self.scanner_frame, self.history_frame]:
            frame.pack_forget()
    
    # User authentication methods
    def register(self):
        """Register a new user."""
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        if self.db.register_user(username, password):
            messagebox.showinfo("Success", "Registration successful. You can now login.")
            # Clear registration fields
            self.reg_username.delete(0, tk.END)
            self.reg_password.delete(0, tk.END)
            self.reg_confirm_password.delete(0, tk.END)
            # Show login page
            self.show_login_page()
        else:
            messagebox.showerror("Error", "Registration failed. Username may already exist.")
    
    def login(self):
        """Login a user."""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        user = self.db.login_user(username, password)
        if user:
            self.current_user = user
            messagebox.showinfo("Success", f"Welcome, {username}!")
            
            # Clear login fields
            self.login_username.delete(0, tk.END)
            self.login_password.delete(0, tk.END)
            
            # Show scanner page
            self.show_scanner_page()
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def logout(self):
        """Logout the current user."""
        self.current_user = None
        
        # Clear result text
        self.result_text.delete(1.0, tk.END)
        
        # Show welcome page
        self.show_welcome_page()
        
        messagebox.showinfo("Logout", "You have been logged out.")
    
    # Scanner methods
    def start_scan(self):
        """Start the XSS vulnerability scan."""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scan")
            return
            
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning {url} for XSS vulnerabilities...\n\n")
        
        # Run scan in a separate thread to keep UI responsive
        threading.Thread(target=self.perform_scan, args=(url,), daemon=True).start()
    
    def perform_scan(self, url):
        """Perform the actual scan in a separate thread."""
        try:
            forms = get_all_forms(url)
            self.result_text.insert(tk.END, f"[+] Detected {len(forms)} forms on {url}.\n\n")
            
            vulnerability_found = False
            form_details_text = ""
            payload_used = ""
            
            for i, form in enumerate(forms, 1):
                form_details = get_form_details(form)
                form_details_text = str(form_details)
                self.result_text.insert(tk.END, f"Form #{i}:\n{form_details_text}\n\n")
                
                for payload in xss_payloads:
                    try:
                        self.result_text.insert(tk.END, f"Testing payload: {payload}\n")
                        response = submit_form(form_details, url, payload)
                        
                        if payload in response.text:
                            vulnerability_found = True
                            payload_used = payload
                            self.result_text.insert(tk.END, "XSS VULNERABILITY DETECTED!\n")
                            self.result_text.insert(tk.END, f"Payload: {payload}\n")
                            self.result_text.insert(tk.END, f"Form: {form_details}\n\n")
                            break
                    except Exception as e:
                        self.result_text.insert(tk.END, f"Error testing payload: {str(e)}\n")
            
            if not vulnerability_found:
                self.result_text.insert(tk.END, "No XSS vulnerabilities detected.\n")
            
            # Save scan result to database
            if self.current_user:
                self.db.save_scan_result(
                    self.current_user['id'], 
                    url, 
                    vulnerability_found, 
                    form_details_text, 
                    payload_used
                )
                
        except Exception as e:
            self.result_text.insert(tk.END, f"Error during scan: {str(e)}\n")
    
    # History methods
    def load_history(self):
        """Load scan history for the current user."""
        if not self.current_user:
            return
            
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        # Get history from database
        history = self.db.get_user_scan_history(self.current_user['id'])
        
        # Populate treeview
        for item in history:
            scan_date = item['scan_date'].strftime('%Y-%m-%d %H:%M:%S')
            vulnerability_status = "Detected" if item['vulnerability_found'] else "Not Detected"
            
            self.history_tree.insert(
                "", 
                "end", 
                values=(
                    item['id'], 
                    item['url'], 
                    scan_date, 
                    vulnerability_status, 
                    "Click 'View Details' to see form details"
                )
            )
    
    def view_scan_details(self):
        """Show detailed information for a selected scan."""
        selected_item = self.history_tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a scan from the history")
            return
            
        item_id = self.history_tree.item(selected_item[0], "values")[0]
        
        # Get all history items
        history = self.db.get_user_scan_history(self.current_user['id'])
        
        # Find the selected item
        selected_scan = None
        for item in history:
            if str(item['id']) == str(item_id):
                selected_scan = item
                break
                
        if selected_scan:
            # Create a new window to display details
            detail_window = tk.Toplevel(self.root)
            detail_window.title("Scan Details")
            detail_window.geometry("600x500")
            
            # Details
            ttk.Label(detail_window, text=f"URL: {selected_scan['url']}").pack(padx=20, pady=10, anchor=tk.W)
            ttk.Label(detail_window, text=f"Scan Date: {selected_scan['scan_date']}").pack(padx=20, pady=5, anchor=tk.W)
            ttk.Label(detail_window, text=f"Vulnerability Found: {selected_scan['vulnerability_found']}").pack(padx=20, pady=5, anchor=tk.W)
            
            if selected_scan['payload_used']:
                ttk.Label(detail_window, text=f"Payload Used: {selected_scan['payload_used']}").pack(padx=20, pady=5, anchor=tk.W)
            
            # Form details
            ttk.Label(detail_window, text="Form Details:").pack(padx=20, pady=5, anchor=tk.W)
            
            details_text = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD, height=15)
            details_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            details_text.insert(tk.END, selected_scan['form_details'])
            
            # Close button
            ttk.Button(detail_window, text="Close", command=detail_window.destroy).pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = XSSApp(root)
    root.mainloop()