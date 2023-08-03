import os
import tkinter as tk
from tkinter import simpledialog
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

import base64

loggedIn = False
masterPwd = ""

def hashPassword(password, salt):
    iterations = 100000
    hashedPassword = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return hashedPassword

def derive_key(masterPassword: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(masterPassword.encode()))
    return key

def encryptPassword(masterPassword: str, password: str):
    salt = os.urandom(16)
    key = derive_key(masterPassword, salt)
    fernet = Fernet(key)
    encryptedPassword = fernet.encrypt(password.encode())
    return key, salt, encryptedPassword

def decryptPassword(masterPassword: str, salt: bytes, encryptedPassword: bytes):
    key = derive_key(masterPassword, salt)
    f = Fernet(key)
    decryptedPassword = f.decrypt(encryptedPassword).decode()
    return decryptedPassword

def createDatabaseTable():
    conn = sqlite3.connect("passwords.db")

    conn.execute('''CREATE TABLE IF NOT EXISTS master_password
                 (id INTEGER PRIMARY KEY,
                 hashed_password BLOB NOT NULL,
                 salt TEXT NOT NULL);''')
    
    cursor = conn.execute("SELECT COUNT(*) FROM master_password")
    if cursor.fetchone()[0] == 0:
        masterPassword = simpledialog.askstring("Master Password", "Enter your master password that you would like to secure your passwords with:", show='*')
        salt = os.urandom(16)
        hashedPassword = hashPassword(masterPassword, salt)
        conn.execute("INSERT OR REPLACE INTO master_password (id, hashed_password, salt) VALUES (?, ?, ?)",
                    (1, hashedPassword, salt))
        conn.commit()
    else:
        masterPassword = simpledialog.askstring("Authentication", "Enter your master password:", show='*')
        if checkMasterPassword(conn, masterPassword):
            loggedIn=True
            masterPwd = masterPassword
        else:
            quit()

    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='passwords';")
    if cursor.fetchone() is None:
        conn.execute('''CREATE TABLE passwords
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
             name           TEXT    NOT NULL,
             email          TEXT    NOT NULL,
             salt           BLOB    NOT NULL,
             password       BLOB    NOT NULL);''')
        conn.commit()

    return conn

def storePassword(conn, name: str, email: str, password: str):
    key, salt, encryptedPassword = encryptPassword(masterPwd, password)
    conn.execute("INSERT INTO passwords (name, email, salt, password) VALUES (?, ?, ?, ?)", (name, email, salt, encryptedPassword))
    conn.commit()

def getPasswords(conn):
    cursor = conn.execute("SELECT id, name, email, password FROM passwords")
    return cursor

def getPasswordByID(conn, password_id):
    cursor = conn.execute("SELECT PASSWORD, SALT FROM PASSWORDS WHERE ID=?", (password_id,))
    result = cursor.fetchone()
    if result:
        encrypted_password, salt = result
        decrypted_password = decryptPassword(masterPwd, salt, encrypted_password)
        return decrypted_password
    else:
        return "Password not found"

def deletePassword(conn, id):
    conn.execute("DELETE FROM passwords WHERE id=?", (id,))
    conn.commit()

def checkMasterPassword(conn, enteredPassword):
    cursor = conn.execute("SELECT hashed_password, salt FROM master_password WHERE id=?", (1,))
    row = cursor.fetchone()
    if row:
        hashedPassword, salt = row
        enteredHashedPassword = hashPassword(enteredPassword, salt)
        return hashedPassword == enteredHashedPassword
    return False

def createGui():
    root = tk.Tk()
    root.title("QuickLane Password Manager")
    conn = createDatabaseTable()

    windowWidth = 800
    windowHeight = 400
    screenWidth = root.winfo_screenwidth()
    screenHeight = root.winfo_screenheight()
    x = (screenWidth - windowWidth) // 2
    y = (screenHeight - windowHeight) // 2
    root.geometry(f"{windowWidth}x{windowHeight}+{x}+{y}")

    listBox = tk.Listbox(root, width=40)
    listBox.pack()

    def showPassword(event):
        selected_index = listBox.curselection()
        if selected_index:
            selectedPassword = listBox.get(selected_index[0])
            passwordId = selectedPassword.split(" | ")[0] 

            password = getPasswordByID(conn, passwordId)
            sidebarLabel.config(text=f"Password: {password}")
    
    listBox.bind("<Double-Button-1>", showPassword)

    def updateListbox():
        listBox.delete(0, tk.END)
        passwords = getPasswords(conn)
        for password in passwords:
            passwordId = password[0]
            name = password[1]
            email = password[2]
            listBox.insert(tk.END, f"{passwordId} | {name} - {email}")
            listBox.config(justify=tk.CENTER)

    def addPassword():
        name = nameEntry.get()
        email = emailEntry.get()
        password = passwordEntry.get()
        storePassword(conn, name, email, password)
        updateListbox()
        nameEntry.delete(0, tk.END)
        emailEntry.delete(0, tk.END)
        passwordEntry.delete(0, tk.END)

    nameLabel = tk.Label(root, text="Name:")
    nameLabel.pack()
    nameEntry = tk.Entry(root)
    nameEntry.pack()

    emailLabel = tk.Label(root, text="Email:")
    emailLabel.pack()
    emailEntry = tk.Entry(root)
    emailEntry.pack()

    passwordLabel = tk.Label(root, text="Password:")
    passwordLabel.pack()
    passwordEntry = tk.Entry(root)
    passwordEntry.pack()

    addButton = tk.Button(root, text="Add Password", command=addPassword)
    addButton.pack()

    sidebarLabel = tk.Label(root, text="Password: ")
    sidebarLabel.pack()

    updateListbox()
    root.mainloop()

if __name__ == "__main__":
    createGui()
