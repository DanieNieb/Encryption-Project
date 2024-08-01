from tkinter import *
from tkinter import filedialog
from functools import partial
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

#Encryption and Decryption Algorithm
def Fernet_Encrypter(cp, encrypt):
    with open(filepath, 'rb') as f:
        contents = f.read()

        key = Create_Key(cp)
        fernet = Fernet(key)

        if encrypt:
            result = fernet.encrypt(contents)
        else:
            result = fernet.decrypt(contents)

        with open(filepath, 'wb') as file:
            file.write(result)
        
#Generate a Key
def Create_Key(cp):
    backend = default_backend()
    salt = b''

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(cp, encoding='utf-8')))
    return key

def EFN_Encrypt(cp):
    countPass = 0
    counter = 0
    countPass2 = 3

    while counter < len(cp):
        countPass += ord(cp[counter])
        counter += 1

    with open(filepath, 'rb') as input_file:
        with open('encrypted', 'wb') as output_file:
            while True:
                chunk = input_file.read(8192)
                if not chunk:
                    break

                encrypted_chunk = bytearray(chunk)
                for i in range(len(encrypted_chunk)):
                    encrypted_chunk[i] = (encrypted_chunk[i] + countPass2) % 256

                output_file.write(encrypted_chunk)
    global filename

    filename = str(filepath)
    global filename2
    global filename3
           
    filename2 = filename.split(".")
    filename3 = "."+filename2[1]
    # Delete the original file
    os.remove(filepath)


def EFN_Decrypt(cp):
    countPass = 0
    counter = 0
    countPass2 = 3

    while counter < len(cp):
        countPass += ord(cp[counter])
        counter += 1
    print(filename)
    with open('encrypted', 'rb') as input_file:
        with open('decrypted'+ filename3, 'wb') as output_file:
            while True:
                chunk = input_file.read(8192)
                if not chunk:
                    break

                decrypted_chunk = bytearray(chunk)
                for i in range(len(decrypted_chunk)):
                    decrypted_chunk[i] = (decrypted_chunk[i] - countPass2) % 256

                output_file.write(decrypted_chunk)

    # Delete the encrypted file
    os.remove('encrypted')

# Function to validate the password and run methods based on radio buttons
def validate_encdec(ep, cp):

    if ep.get() == cp.get():
        text = " "
        text_PasswordConfirmed = Label(screen, text=text, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        text_PasswordConfirmed.place(x=330, y=100)

        if algorithm.get() == 1:
            if method.get() == 1:
                Fernet_Encrypter(cp.get(), True)
            elif method.get() == 2:
                Fernet_Encrypter(cp.get(), False)
        elif algorithm.get() == 2:
            if method.get() == 1:
                EFN_Encrypt(cp.get())
            elif method.get() == 2:
                EFN_Decrypt(cp.get())
    else:
        text = "Password not matched"
        text_PasswordConfirmed = Label(screen, text=text, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        text_PasswordConfirmed.place(x=330, y=100)

# Main Screen


def password_screen():

    screen = Tk()
    screen.geometry("400x250")
    screen.configure(bg='#F8F8F8')
    screen.title("Encryption and Decryption")

    # Title label
    text = "Encryption and Decryption"
    text_Titel = Label(screen, text=text, font=(
        "Arial Bold", 16), bg='#F8F8F8', fg='#333333')
    text_Titel.place(x=50, y=20)

    # Password label
    text = "Password:"
    text_Password = Label(screen, text=text, font=(
        "Arial", 13), bg='#F8F8F8', fg='#333333')
    text_Password.place(x=50, y=80)

    # Password textbox
    ep = StringVar()
    passwordTextbox = Entry(screen, textvariable=ep,
                            font=("Arial", 13), show="#")
    passwordTextbox.place(x=150, y=80)

    # Close Button
    Closebtn = Button(screen, text="Close", font=("Arial", 13),
                      bg='light grey', fg='black', command=screen.destroy)
    Closebtn.place(x=300, y=180)

    # Encryption and Decription Window
    def Encr_Decri():
        global screen
        global algorithm
        global method
        screen = Tk()
        screen.geometry("600x300")
        screen.configure(bg='#F8F8F8')
        screen.title("Encryption and Decryption")

        # Browse label
        browse_label = Label(screen, text="Select a file:", font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        browse_label.place(x=50, y=30)

        # Search bar
        search_bar = Entry(screen, font=("Arial", 15))
        search_bar.place(x=210, y=30, width=280)

        # Browse button
        
        def browse_file():
            global filepath
            filepath = filedialog.askopenfilename()
            
            search_bar.delete(0, END)
            search_bar.insert(0, filepath)

        # Browse button to get path on computer
        browse_button = Button(screen, text="Browse", font=(
            "Arial", 13), bg='light grey', fg='black', command=browse_file)
        browse_button.place(x=500, y=25)

        # Close button on encr_decr Form
        Closebtn = Button(screen, text="Close", font=(
            "Arial", 13), bg='light grey', fg='black', command=screen.destroy)
        Closebtn.place(x=500, y=250)

        # Password label on encr_decr Form
        text = "Password:"
        text_Password = Label(screen, text=text, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        text_Password.place(x=90, y=100)

        # Password textbox on encr_decr Form
        cp = StringVar()
        checkpasswordTextbox = Entry(
            screen, textvariable=cp, font=("Arial", 15), show="#")
        checkpasswordTextbox.place(x=210, y=100)

        # Radio Buttons for DES Algorithm and Own Algorithm  EFN (Encryption for noobs)
        # Select label
        select_label = Label(screen, text="Select Algorithm:", font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        select_label.place(x=50, y=150)

        algorithm = IntVar()
        algorithm.get()

        rdoEncrypt = Radiobutton(screen, text="Fernet", variable=algorithm, value=1, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        rdoEncrypt.place(x=220, y=150)

        rdoDecript = Radiobutton(screen, text="EFN", variable=algorithm, value=2, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        rdoDecript.place(x=320, y=150)

        # Radio Buttons Encryption and Decryption
        method = IntVar()
        method.get()

        rdoEncrypt = Radiobutton(screen, text="Encrypt", variable=method, value=1, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        rdoEncrypt.place(x=150, y=200)

        rdoDecript = Radiobutton(screen, text="Decrypt", variable=method, value=2, font=(
            "Arial", 15), bg='#F8F8F8', fg='#333333')
        rdoDecript.place(x=350, y=200)

        # Code that validates the password
        validatepassword = partial(validate_encdec, ep, cp)

        # Test Password
        Runbtn = Button(screen, text="Run", font=("Arial", 13),
                        bg='light grey', fg='black', command=validatepassword)
        Runbtn.place(x=50, y=250)

        screen.mainloop()

    # Password function written
    def save_password():
        password = passwordTextbox.get()

        # Close the password screen
        screen.destroy()

        # Create the Encr_Decri window
        Encr_Decri()

    # Set Password
    SetPasswordbtn = Button(screen, text="Set Password", font=(
        "Arial", 13), bg='light grey', fg='black', command=save_password)
    SetPasswordbtn.place(x=150, y=130)

    screen.mainloop()


password_screen()
