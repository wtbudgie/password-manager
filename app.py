import os, sqlite3, secrets, keyring, base64

from tkinter import Tk, Listbox, END, CENTER, Label, Entry, Button
from tkinter import simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from passlib.hash import pbkdf2_sha256

serviceId = "QuickLanePasswordManager"

def hashPassword(password, salt):
    hashedPassword = pbkdf2_sha256.hash(password, salt=salt, rounds=480000)
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

def encryptPassword(password: str):
    salt = secrets.token_bytes(16)
    key = derive_key(keyring.get_password(serviceId, 'MasterPassword'), salt)
    fernet = Fernet(key)
    encryptedPassword = fernet.encrypt(password.encode())
    return key, salt, encryptedPassword

def decryptPassword(salt: bytes, encryptedPassword: bytes):
    print(keyring.get_password(serviceId, 'MasterPassword'))
    key = derive_key(keyring.get_password(serviceId, 'MasterPassword'), salt)
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
            keyring.set_password(serviceId, 'MasterPassword', masterPassword)
            print(keyring.get_password(serviceId, 'MasterPassword'))
            
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
    key, salt, encryptedPassword = encryptPassword(password)
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
        decrypted_password = decryptPassword(salt, encrypted_password)
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
    root = Tk()
    root.title("QuickLane Password Manager")

    windowWidth = 800
    windowHeight = 400
    screenWidth = root.winfo_screenwidth()
    screenHeight = root.winfo_screenheight()
    x = (screenWidth - windowWidth) // 2
    y = (screenHeight - windowHeight) // 2
    root.geometry(f"{windowWidth}x{windowHeight}+{x}+{y}")

    listBox = Listbox(root, width=40)
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
        listBox.delete(0, END)
        passwords = getPasswords(conn)
        for password in passwords:
            passwordId = password[0]
            name = password[1]
            email = password[2]
            listBox.insert(END, f"{passwordId} | {name} - {email}")
            listBox.config(justify=CENTER)

    sidebarLabel = Label(root, text="Password: ")
    sidebarLabel.pack()

    def addPassword():
        name = nameEntry.get()
        email = emailEntry.get()
        password = passwordEntry.get()
        storePassword(conn, name, email, password)
        updateListbox()
        nameEntry.delete(0, END)
        emailEntry.delete(0, END)
        passwordEntry.delete(0, END)

    nameLabel = Label(root, text="Name:")
    nameLabel.pack()
    nameEntry = Entry(root)
    nameEntry.pack()

    emailLabel = Label(root, text="Email:")
    emailLabel.pack()
    emailEntry = Entry(root)
    emailEntry.pack()

    passwordLabel = Label(root, text="Password:")
    passwordLabel.pack()
    passwordEntry = Entry(root)
    passwordEntry.pack()

    addButton = Button(root, text="Add Password", command=addPassword)
    addButton.pack()

    updateListbox()
    root.mainloop()

if __name__ == "__main__":
    conn = createDatabaseTable()
    createGui()
