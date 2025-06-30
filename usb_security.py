
import os
import sys
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox
import random
import string
import smtplib
import webbrowser
from PIL import Image, ImageTk
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

LOG_FILE = "usb_actions.log"

# Encrypted sender credentials (Base64)
ENCRYPTED_EMAIL = "ZnJlZWZpcmVnYW1pbmd5dDcxOEBnbWFpbC5jb20="  # Replace with your base64 encoded email
ENCRYPTED_PASSWORD = "bmp2bSB2c2lrIGtsemYgaHp4cQ=="    # Replace with your base64 encoded app password

def decrypt(encoded_text):
    return base64.b64decode(encoded_text.encode()).decode()

# Decrypted credentials
SENDER_EMAIL = decrypt(ENCRYPTED_EMAIL)
SENDER_PASSWORD = decrypt(ENCRYPTED_PASSWORD)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "ADMIN"

def log_action(action):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action}\n")

def generate_random_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def send_password_via_email(sender_email, sender_password, recipient_email, password):
    subject = "🔐 Your One-Time USB Access Password"

    body = f"""
Hello ,

Here is your one-time access password for the USB Security Tool:

🔐 Password: {password}

This project was developed to enhance physical system security by allowing administrators to enable or disable USB ports based on controlled access.

🔒 Project Strengths:
- Prevents unauthorized data transfers via USB
- Sends temporary password via secure email
- Admin-protected with login attempts limit
- Real-time logging and activity tracking
- Clean, user-friendly GUI built in Python

Thank you for using our secure solution.

Developed by:
Abiram S & Aneesh Prabu P
Supraja Technologies
    """

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        messagebox.showerror("Email Error", f"Failed to send email: {e}")
        return False

def disable_usb():
    try:
        os.system('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f')
        messagebox.showinfo("USB Disabled", "USB ports have been disabled.")
        log_action("USB disabled")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to disable USB: {e}")
        log_action(f"Failed to disable USB: {e}")

def enable_usb():
    try:
        os.system('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 3 /f')
        messagebox.showinfo("USB Enabled", "USB ports have been enabled.")
        log_action("USB enabled")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to enable USB: {e}")
        log_action(f"Failed to enable USB: {e}")

def verify_password_and_execute(action_func):
    recipient_email = simpledialog.askstring("Recipient Email", "Enter the email to receive the access password:")
    if not recipient_email:
        return

    generated_password = generate_random_password()
    if send_password_via_email(SENDER_EMAIL, SENDER_PASSWORD, recipient_email, generated_password):
        log_action(f"Access password sent to {recipient_email}")
        entered = simpledialog.askstring("Verification", "Enter the password sent to your email:", show='*')
        if entered and entered == generated_password:
            action_func()
        else:
            messagebox.showerror("Access Denied", "Incorrect password entered.")
            log_action("Access denied due to incorrect password")

def open_project_info():
    try:
        webbrowser.open_new_tab(html_path)
    except Exception as e:
        messagebox.showerror("Error", f"Unable to open project info page: {e}")

base_path=os.path.dirname(os.path.abspath(__name__))
print(base_path)
logo_path=os.path.join(base_path,"logo1.ico")
bottom_path=os.path.join(base_path,"bot.jpg")
html_path=os.path.join(base_path,"demo.html")
background_path=os.path.join(base_path,"wa.jpeg")
question_path=os.path.join(base_path,"ques.png")
enable_path=os.path.join(base_path,"ena.jpg")
disable_path=os.path.join(base_path,"disa.jpg")

def resource_path(relative_path):
    """Get the absolute path to resource, works for PyInstaller."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

logo_path = resource_path("logo.jpg")
bottom_path = resource_path("bot.jpg")
background_path = resource_path("wa.jpeg")
question_path = resource_path("ques.png")
enable_path = resource_path("ena.jpg")
disable_path = resource_path("disa.jpg")
html_path = resource_path("ProjectDetails.html")

def admin_login():
    attempts = 0
    max_attempts = 3
    while attempts < max_attempts:
        username = simpledialog.askstring("Admin Login", "Enter admin username:")
        password = simpledialog.askstring("Admin Login", "Enter admin password:", show='*')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            messagebox.showinfo("Login Successful", "Welcome You Have Admin! Access")
            return True
        else:
            attempts += 1
            messagebox.showerror("Login Failed", f"Invalid credentials. Attempt {attempts} of {max_attempts}")
    return False

# GUI Setup
root = tk.Tk()
root.withdraw()  # Hide until login is successful

if not admin_login():
    sys.exit()

root.deiconify()
root.title("USB Security Tool")
root.geometry("300x300")

# Hover effect functions for image buttons
def on_enter(widget):
    widget.config(bg="#f40000", relief="sunken")

def on_leave(widget):
    widget.config(bg=root["bg"], relief="flat")



# Load and resize button images
ena_img = Image.open(enable_path).resize((100, 60), Image.Resampling.LANCZOS)
disa_img = Image.open(disable_path).resize((100, 60), Image.Resampling.LANCZOS)
photo_ena = ImageTk.PhotoImage(ena_img)
photo_disa = ImageTk.PhotoImage(disa_img)

# Create a frame for placing image buttons side by side
button_frame = tk.Frame(root, bg=root["bg"])
button_frame.pack(pady=10)

btn_enable = tk.Button(button_frame, image=photo_ena, command=lambda: verify_password_and_execute(enable_usb), borderwidth=0, bg=root["bg"], relief="flat", activebackground="#d0f0f0")
btn_enable.grid(row=0, column=0, padx=10)
btn_enable.bind("<Enter>", lambda e: on_enter(btn_enable))
btn_enable.bind("<Leave>", lambda e: on_leave(btn_enable))

btn_disable = tk.Button(button_frame, image=photo_disa, command=lambda: verify_password_and_execute(disable_usb), borderwidth=0, bg=root["bg"], relief="flat", activebackground="#ffd6d6")
btn_disable.grid(row=0, column=1, padx=10)
btn_disable.bind("<Enter>", lambda e: on_enter(btn_disable))
def animated_button(btn, color_hover, color_normal):
    def on_enter(e): btn.config(bg=color_hover)
    def on_leave(e): btn.config(bg=color_normal)
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

btn_logs = tk.Button(root, text="View Logs", command=lambda: os.system(f'start notepad {LOG_FILE}'),
          bg="blue", fg="white", height=2, width=20)
btn_logs.pack(pady=10)
animated_button(btn_logs, "#74b9ff", "blue")

btn_info = tk.Button(root, text="Project Info", command=open_project_info,
          bg="purple", fg="white", height=2, width=20)
btn_info.pack(pady=10)
animated_button(btn_info, "#a29bfe", "purple")

root.mainloop()
