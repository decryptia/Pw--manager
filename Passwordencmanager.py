import base64
import os
import random
import string
import customtkinter as ct
from tkinter import messagebox

import subprocess

ct.set_appearance_mode("dark")
ct.set_appearance_mode("blue")

global encrypted_text

window = ct.CTk()
window.title("password manager")
window.geometry("600x340")

# Functions
# For getting the credentials

def decryptData(encrypted_text):
    base64_decrypted = base64.b64decode(encrypted_text).decode()
    rot_decrypted = rot13_decode(base64_decrypted)
    return rot_decrypted

def dec_final(key_master_pas):
    global encrypted_text

    key_master_pw = key_master_pas
    with open("password.txt", "r") as file:
        saved_password = file.read().strip()

    if saved_password == key_master_pw:

        try:
            with open("decryptedcredentials.txt", "w") as f:
                contents = encrypted_text.split("\n")[:-1]
                for line in contents:
                    site, user_id, password = line.strip().split(",")
                    decrypted_password = decryptData(password)
                    x = f"Site: {site}, User id: {user_id}, Password: {decrypted_password}"
                    f.write(x)
                subprocess.Popen(["notepad.exe", "decryptedcredentials.txt"])
            for widget in window.winfo_children():
                widget.destroy()

            key_master_password = ct.CTkLabel(
                window, text="Enter the key_master password generated to decrypted the file")
            key_master_password.pack(pady=17)

            home_btn = ct.CTkButton(
                window, text="Take me Home", command=first_window)
            home_btn.pack(pady=4)

        except:
            print("error")
    else:
        ct.CTkLabel(window, text="Error: Passwords do not match.").pack()

def key_master():
    for widget in window.winfo_children():
        widget.destroy()

    key_master_password = ct.CTkLabel(
        window, text="Enter the key_master password u generated to decrypted the file")
    key_master_password.pack(pady=17)

    key_master_password = ct.CTkLabel(window, text="key_master password:")
    key_master_password.pack(pady=5)

    key_master_password_entry = ct.CTkEntry(window, show="*")
    key_master_password_entry.pack(pady=5)

    submit_button = ct.CTkButton(window, text="Submit", command=lambda: pw_checking(
        key_master_password_entry))
    submit_button.pack(pady=4)

def pw_checking(key_master_password_entry):

    raw_pwd = key_master_password_entry.get()

    # key_master_pw = key_master_password.get()
    with open("password.txt", "r") as file:
        raw_pw = file.read().strip()
    if raw_pwd == raw_pw:
        saved_content()
    else:
        ct.CTkLabel(window, text="Error: Passwords do not match.").pack()

def next_window():

    for widget in window.winfo_children():
        widget.destroy()

    key_master_password = ct.CTkLabel(
        window, text="Enter a key_master Password that will help you to decrypted the file")
    key_master_password.pack(pady=17)

    key_master_password = ct.CTkLabel(window, text="key_master password:")
    key_master_password.pack(pady=5)

    key_master_password = ct.CTkEntry(window, show="*")
    key_master_password.pack(pady=5)

    re_key_master_password = ct.CTkLabel(window, text="Retype the key_master password")
    re_key_master_password.pack(pady=5)

    re_key_master_password = ct.CTkEntry(window, show="*")
    re_key_master_password.pack(pady=5)

    submit_button = ct.CTkButton(window, text="Submit", command=lambda: passcheck(
        key_master_password, re_key_master_password))
    submit_button.pack(pady=4)

def passcheck(key_master_password, re_key_master_password):
    key_master_pas = key_master_password.get()
    re_key_master_pas = re_key_master_password.get()
    if key_master_pas == re_key_master_pas:
        with open("password.txt", "w") as file:
            file.write(key_master_pas)
        dec_final(key_master_pas)
        messagebox.showinfo("info", "password has been saved successfully !!")
        decryptData(encrypted_text)
    else:
        # Show an error message
        ct.CTkLabel(window, text="Error: Passwords do not match.").pack()

def rot13_decode(text):
    result = ""
    for char in text:
        ascii_value = ord(char)
        if 65 <= ascii_value <= 90:
            result += chr((ascii_value - 78) % 26 + 65)
        elif 97 <= ascii_value <= 122:
            result += chr((ascii_value - 110) % 26 + 97)
        else:
            result += char
    return result

def rot13_encode(text):
    result = ""
    for char in text:
        ascii_value = ord(char)
        if 65 <= ascii_value <= 90:
            result += chr((ascii_value - 65 + 13) % 26 + 65)
        elif 97 <= ascii_value <= 122:
            result += chr((ascii_value - 97 + 13) % 26 + 97)
        else:
            result += char
    return result

def encryptData(data):
    # Encryption process
    rot_encrypted = rot13_encode(data)
    base64_encrypted = base64.b64encode(rot_encrypted.encode()).decode()
    return base64_encrypted

def writedata(websiteName_entry, Username_entry, password_entry, root):
    global encrypted_text, empty

    web_name = websiteName_entry.get()
    user_name = Username_entry.get()
    password = password_entry.get()

    if web_name != "" and user_name != "" and password != "":
        encrypted_text = (f'{web_name},{user_name},{encryptData(password)}\n')
        with open("details.txt", "a") as file:
            file.write(encrypted_text)
        subprocess.Popen(["notepad.exe", "details.txt"])

        root.destroy()
        a = messagebox.showinfo(
            'Info', "The data u entered have been sucessfully encrypted and saved to details.txt")
        if a == "ok":
            b = messagebox.askquestion(
                "Decrypt", "Do you want to decrypt the file?")
            if b == "yes":
                next_window()

            else:
                first_window()

    else:
        messagebox.showerror(
            'Error', "entry field can not be empty !!")

def readdata():
    '''The function is used for reading the encrypted credentials from a file.'''

    with open("details.txt", "r") as file:
        encrypted_text = file.read()
    decrypted_text = decryptData(encrypted_text)
    print(decrypted_text)

def getdetails():
    # Credentials Input

    root = ct.CTk()
    root.geometry("340x220")

    for widget in window.winfo_children():
        widget.destroy()
    websiteName_label = ct.CTkLabel(root, text="Website Name:")
    websiteName_label.pack()

    websiteName_entry = ct.CTkEntry(root)
    websiteName_entry.pack()

    Username_label = ct.CTkLabel(root, text="Username:")
    Username_label.pack()

    Username_entry = ct.CTkEntry(root)
    Username_entry.pack()

    password_label = ct.CTkLabel(root, text="Password:")
    password_label.pack()

    password_entry = ct.CTkEntry(root, show="*", )
    password_entry.pack()

    submit_button = ct.CTkButton(
        root, text="Submit", command=lambda: writedata(websiteName_entry, Username_entry, password_entry, root))
    submit_button.pack()

    root.mainloop()

def show(website_entry, userid_entry):

    web_name = website_entry.get()
    saved_user = userid_entry.get()

    data = []
    found = False
    with open("details.txt", 'r') as f:
        contents = f.read().split("\n")[:-1]
        for line in contents:
            site, user_id, password = line.strip().split(",")
            decrypted_password = decryptData(password)
            temp = {
                'Site': site,
                'User id': user_id,
                'Password': decrypted_password
            }
            data.append(temp)

    for item in data:
        if item['Site'] == web_name and item['User id'] == saved_user:
            found = True
            with open("cred_to_show.txt", "w") as file:
                x = f"Site: {item['Site']}, User id: {item['User id']}, Password: {item['Password']}"
                file.write(x)
                subprocess.Popen(["notepad.exe", "cred_to_show.txt"])

    if not found:
        msg_label = ct.CTkLabel(
            window, text="No data found for the website.")
        msg_label.pack(pady=10)

    back_button = ct.CTkButton(
        window, text="Back", command=first_window)
    back_button.pack(pady=4)

def saved_content():
    for widget in window.winfo_children():
        widget.destroy()

    msg_label = ct.CTkLabel(
        window, text="Hello, You can view old content with the key_master password.")
    msg_label.pack(pady=10)

    website_label = ct.CTkLabel(
        window, text="Enter the website name you have saved: ")
    website_label.pack(pady=10)

    website_entry = ct.CTkEntry(window)
    website_entry.pack()

    userid_label = ct.CTkLabel(
        window, text="Enter the user id you have saved: ")
    userid_label.pack(pady=10)

    userid_entry = ct.CTkEntry(window)
    userid_entry.pack()

    submit_button = ct.CTkButton(
        window, text="Submit", command=lambda: show(website_entry, userid_entry))
    submit_button.pack(pady=4)

def terminate():
    exit()

def first_window():
    for widget in window.winfo_children():
        widget.destroy()

    msg_label = ct.CTkLabel(window, text="Hello, welcome to PassGen"
                            )
    msg_label.pack(pady=10)
    msg_label = ct.CTkLabel(window,
                            text="A simple,easy to use password manager,to store all your important credentials."
                            )
    msg_label.pack(pady=10)

    old_label = ct.CTkButton(
        window, text="Click here to view old encrypted passwords", command=key_master, fg_color="#17A589")
    old_label.pack(pady=15)

    new_label = ct.CTkButton(
        window, text="Click here to create new encrypted passwords", command=getdetails, fg_color="#17A589")
    new_label.pack(pady=12)

    exit_btn = ct.CTkButton(
        window, text="Exit", command=terminate, fg_color="#17A589")
    exit_btn.pack(pady=8)

first_window()

window.mainloop()

