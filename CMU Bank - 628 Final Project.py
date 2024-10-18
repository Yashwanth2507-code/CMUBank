#!/usr/bin/env python
# coding: utf-8

# In[ ]:


mport tkinter as tk
from tkinter import messagebox
import sqlite3
from tkinter import font
import bcrypt
from tkcalendar import DateEntry
from PIL import Image, ImageTk, ImageFilter, ImageSequence

def create_table():
    conn = sqlite3.connect('users_data.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            phone TEXT NOT NULL,
            card_number TEXT,
            cvv TEXT,
            expiry_date TEXT
        )
    ''')

    conn.commit() 
    conn.close()

def validate_card_details(card_number, cvv, expiry_date):

    if len(card_number) != 16: 
        messagebox.showerror("Invalid Card Number", "Card Number must have 16 digits.")
        return False

    if len(cvv) != 3:
        messagebox.showerror("Invalid CVV", "CVV must have 3 digits.")
        return False

    # Additional validation for expiry date can be added if necessary

    return True

def validate_entry(value):
    # Check if the value is a valid integer
    try:
        int(value)
        return True
    except ValueError:
        return False
    
def card_details_window(username):
    
    card_window = tk.Toplevel(root)
    card_window.title("Card Details")
    card_window.geometry("1600x600")
    set_background(card_window, "C:\\Users\\Yashwanth\\OneDrive\\Desktop\\Yashwanth project\\img2.jpg")


    card_window.geometry("{0}x{1}+0+0".format(card_window.winfo_screenwidth(), card_window.winfo_screenheight()))

    tk.Label(card_window, text="Enter Card Details").pack()

    label_space = tk.Label(card_window, text="")
    label_space.pack(pady=100)

    label_card_number = tk.Label(card_window, text="Card Number:")
    label_card_number.pack()
    entry_card_number = tk.Entry(card_window)
    entry_card_number.pack(pady=10)

    label_cvv = tk.Label(card_window, text="CVV:")
    label_cvv.pack()
    entry_cvv = tk.Entry(card_window)
    entry_cvv.pack(pady=10)

    label_expiry_date = tk.Label(card_window, text="Expiry Date:")
    label_expiry_date.pack()
    entry_expiry_date = DateEntry(card_window, width=12, background='darkblue', foreground='white', date_pattern='yyyy-mm-dd')
    entry_expiry_date.pack(pady=10)

    button_sign_up = tk.Button(card_window, text="SignUp", command=lambda: save_card_details_and_login(card_window, username, entry_card_number.get(), entry_cvv.get(), entry_expiry_date.get()))
    button_sign_up.pack()

def save_card_details_and_login(window, username, card_number, cvv, expiry_date):
    if not validate_card_details(card_number, cvv, expiry_date):
        return
    conn = sqlite3.connect('users_data.db')
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET card_number=?, cvv=?, expiry_date=? WHERE username=?", (card_number, cvv, expiry_date, username))
    conn.commit()

    conn.close()

    window.destroy()
    login()

def signup():
    def create_user():
        firstname = entry_firstname.get()
        lastname = entry_lastname.get()
        phone = entry_phone.get()
        new_username = entry_new_username.get()
        new_password = entry_new_password.get()
        confirm_password = entry_confirm_password.get()

        if not validate_entry(phone):
            messagebox.showerror("Phone Number Checker", "Phone Number must be digits. Please try again.",parent = signup_window)
            return

        if new_password != confirm_password:
            messagebox.showerror("Password Mismatch", "Passwords do not match. Please try again.",parent = signup_window)
            return

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('users_data.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (new_username,))
        existing_user = cursor.fetchone()

        if existing_user:
            messagebox.showerror("Username Exists", "Username already exists. Please choose a different username.",parent = signup_window)
        else:
            cursor.execute("INSERT INTO users (username, password, firstname, lastname, phone) VALUES (?, ?, ?, ?, ?)",
                           (new_username, hashed_password, firstname, lastname, phone))
            conn.commit()
            messagebox.showinfo("Signup Successful", "Account created successfully!",parent = signup_window)

            # Close the signup window
            signup_window.destroy()

            # Open another page for card details
            card_details_window(new_username)

        conn.close()

    
    signup_window = tk.Toplevel(root)
    signup_window.title("Signup Page")
    signup_window.geometry("1600x600")
    set_background(signup_window, "C:\\Users\\Yashwanth\\OneDrive\\Desktop\\Yashwanth project\\img2.jpg")


    signup_window.geometry("{0}x{1}+0+0".format(signup_window.winfo_screenwidth(), signup_window.winfo_screenheight()))

    label_space = tk.Label(signup_window, text="")
    label_space.pack(pady=70)

    label_firstname = tk.Label(signup_window, text="First Name:")
    label_firstname.pack()
    entry_firstname = tk.Entry(signup_window)
    entry_firstname.pack(pady=10)

    label_lastname = tk.Label(signup_window, text="Last Name:")
    label_lastname.pack()
    entry_lastname = tk.Entry(signup_window)
    entry_lastname.pack(pady=10)

    label_phone = tk.Label(signup_window, text="Phone Number:")
    label_phone.pack()
    entry_phone = tk.Entry(signup_window)
    entry_phone.pack(pady=10)

    label_new_username = tk.Label(signup_window, text="Username:")
    label_new_username.pack()
    entry_new_username = tk.Entry(signup_window)
    entry_new_username.pack(pady=10)

    label_new_password = tk.Label(signup_window, text="Password:")
    label_new_password.pack()
    entry_new_password = tk.Entry(signup_window, show="*")
    entry_new_password.pack(pady=10)

    label_confirm_password = tk.Label(signup_window, text="Confirm Password:")
    label_confirm_password.pack()
    entry_confirm_password = tk.Entry(signup_window, show="*")
    entry_confirm_password.pack(pady=10)

    button_signup = tk.Button(signup_window, text="Save", command=create_user)
    button_signup.pack()


def welcome_page(username):
    welcome_window = tk.Toplevel(root)
    welcome_window.title("Welcome Page")
    welcome_window.geometry("1600x600")
    set_background(welcome_window, "C:\\Users\\Yashwanth\\OneDrive\\Desktop\\Yashwanth project\\img2.jpg")
    welcome_window.geometry("{0}x{1}+0+0".format(welcome_window.winfo_screenwidth(), welcome_window.winfo_screenheight()))

    label_space = tk.Label(welcome_window, text="")
    label_space.pack(pady=100)

    label_welcome = tk.Label(welcome_window, text="Hello " + username)
    label_welcome.pack(pady=10)

    def logout():
        welcome_window.destroy()
        login()

    button_logout = tk.Button(welcome_window, text="Logout", command=logout)
    button_logout.pack(pady=10)

    def update_pin_page():
        welcome_window.withdraw()  # Hide the welcome window

        def save_pin():
            # Implement the logic to save PIN in the database
            new_pin = entry_newpin.get()
            confirm_pin = entry_confirmpin.get()

            if new_pin == confirm_pin:
                messagebox.showinfo("PIN Updated", "PIN updated successfully!",parent= welcome_window)
                welcome_page(username)
            else:
                messagebox.showerror("Error", "New PIN and Confirm PIN do not match.",parent= update_pin_window)
            update_pin_window.destroy()

        update_pin_window = tk.Toplevel(root)
        update_pin_window.title("Update PIN")
        update_pin_window.geometry("1600x600")
        set_background(update_pin_window, "C:\\Users\\Yashwanth\\OneDrive\\Desktop\\Yashwanth project\\img2.jpg")
        update_pin_window.geometry("{0}x{1}+0+0".format(update_pin_window.winfo_screenwidth(), update_pin_window.winfo_screenheight()))

        label_space = tk.Label(update_pin_window, text="")
        label_space.pack(pady=100)

        label_oldpin = tk.Label(update_pin_window, text="Default PIN: 1234")
        label_oldpin.pack(pady=10)

        label_newpin = tk.Label(update_pin_window, text="New PIN:")
        label_newpin.pack()
        entry_newpin = tk.Entry(update_pin_window)
        entry_newpin.pack(pady=10)

        label_confirmpin = tk.Label(update_pin_window, text="Confirm PIN:")
        label_confirmpin.pack()
        entry_confirmpin = tk.Entry(update_pin_window, show='*')
        entry_confirmpin.pack(pady=10)

        button_save = tk.Button(update_pin_window, text="Save", command=save_pin)
        button_save.pack(pady=10)

    button_update_pin = tk.Button(welcome_window, text="Update PIN", command=update_pin_page)
    button_update_pin.pack(pady=10)

    def update_password_page():
        welcome_window.withdraw() 
        update_password_window = tk.Toplevel(root)
        update_password_window.title("Update Password")
        update_password_window.geometry("1600x600")
        set_background(update_password_window, "C:\\Users\\Yashwanth\\OneDrive\\Desktop\\Yashwanth project\\img2.jpg")

        update_password_window.geometry("{0}x{1}+0+0".format(update_password_window.winfo_screenwidth(), update_password_window.winfo_screenheight()))

        label_space = tk.Label(update_password_window, text="")
        label_space.pack(pady=100)

        label_oldpassword = tk.Label(update_password_window, text="Old Password:")
        label_oldpassword.pack()
        entry_oldpassword = tk.Entry(update_password_window)
        entry_oldpassword.pack(pady=10)

        label_newpassword = tk.Label(update_password_window, text="New Password:")
        label_newpassword.pack()
        entry_newpassword = tk.Entry(update_password_window)
        entry_newpassword.pack(pady=10)

        label_confirmpassword = tk.Label(update_password_window, text="Confirm Password:")
        label_confirmpassword.pack()
        entry_confirmpassword = tk.Entry(update_password_window, show='*')
        entry_confirmpassword.pack(pady=10)

        

        def save_updated_password():
            conn = sqlite3.connect('users_data.db')
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            users_data = cursor.fetchone()
            old_password_from_db = users_data[2]  # Assuming password is the 3rd column (adjust if needed)
            entered_old_password = entry_oldpassword.get().encode('utf-8')  # Encode the entered password

            if bcrypt.checkpw(entered_old_password, old_password_from_db):
                # Old password matches, proceed with updating the password
                new_password = entry_newpassword.get()
                confirm_password = entry_confirmpassword.get()

                if new_password == confirm_password:
                    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_new_password, username))
                    conn.commit()
                    conn.close()
                    messagebox.showinfo("Password Updated", "Password updated successfully!")
                    update_password_window.destroy()
                    welcome_page(username)
                else:
                    messagebox.showerror("Mismatched Passwords", "New Password and Confirm Password do not match. Please try again.")
            else:
                messagebox.showerror("Incorrect Password", "Incorrect old password. Please try again.")
            update_password_window.destroy()

        button_save = tk.Button(update_password_window, text="Save", command=save_updated_password)
        button_save.pack(pady=10)

    button_update_password = tk.Button(welcome_window, text="Update Password", command=update_password_page)
    button_update_password.pack(pady=10)





def set_background(window, image_path):
    image = Image.open(image_path)
    image = image.resize((1300,800))  # You can apply other filters if needed
    photo = ImageTk.PhotoImage(image)

    label = tk.Label(window, image=photo)
    label.image = photo
    label.place(x=0, y=0, relwidth=1, relheight=1)



def login():
    def on_login_success(username):
        welcome_page(username)

    username = entry_username.get()
    password = entry_password.get()

    if not username or not password:
        messagebox.showerror("Incomplete Information", "Please enter both username and password.",parent = root)
        return

    conn = sqlite3.connect('users_data.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    users_data = cursor.fetchone()

    if users_data:
        if bcrypt.checkpw(password.encode('utf-8'), users_data[2]):
            messagebox.showinfo("Login Successful", "Welcome, " + username + "!", parent = root)
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)
            on_login_success(username)
        else:
            messagebox.showerror("Incorrect Password", "Incorrect password for " + username + ". Please try again.", parent = root)
    else:
        messagebox.showerror("Invalid Username", "Username " + username + " not found. Please signup or try a different username.", parent = root)

    conn.close()



root = tk.Tk()
root.title("Central Michigan Bank")
root.geometry("1600x600")
set_background(root, "C:\\Users\\Yashwanth\\OneDrive\\Desktop\\Yashwanth project\\img2.jpg")


create_table()

bold_font = font.Font(weight="bold")

label_space = tk.Label(root, text="")
label_space.pack(pady=100)

label_name = tk.Label(root, text="Central Michigan Bank", font=bold_font, fg='maroon')
label_name.pack(pady=20)

label_username = tk.Label(root, text="Username:")
label_username.pack()
entry_username = tk.Entry(root)
entry_username.pack(pady=10)

label_password = tk.Label(root, text="Password:")
label_password.pack()
entry_password = tk.Entry(root, show="*")
entry_password.pack(pady=10)

button_login = tk.Button(root, text="Login", command=login)
button_login.pack(pady=10)

button_signup = tk.Button(root, text="Signup", command=signup)
button_signup.pack()

root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))
root.mainloop()

