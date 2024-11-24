import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string

def is_pwd_strong(password):
    has_uppercase = any(char.isupper() for char in password)
    has_numbers = any(char.isdigit() for char in password)
    has_symbols = any(char in string.punctuation for char in password)
    return len(password) >= 8 and has_uppercase and has_numbers and has_symbols

def gen_pwd(length, use_uppercase, use_numbers, use_symbols):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ""
    numbers = string.digits if use_numbers else ""
    symbols = string.punctuation if use_symbols else ""

    
    all_characters = lowercase + uppercase + numbers + symbols
    if not all_characters.strip():
        all_characters = lowercase  

    while True:
        password = ''.join(secrets.choice(all_characters) for _ in range(length))
        return password

def generate_password():
    try:
        length = int(length_var.get())
        if length < 8:
            raise ValueError("Password length must be at least 8 characters.")

        password = gen_pwd(
            length=length,
            use_uppercase=uppercase_var.get(),
            use_numbers=numbers_var.get(),
            use_symbols=symbols_var.get(),
        )
        password_output.set(password)

    except ValueError as e:
        messagebox.showerror("Input Error", str(e))
    except Exception as e:
        messagebox.showerror("Error", str(e))


def copy_to_clipboard():
    password = password_output.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()
        messagebox.showinfo("Success", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy!")



root = tk.Tk()
root.title("Password Generator")
root.geometry("400x300")


length_var = tk.StringVar(value="8")
uppercase_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)
password_output = tk.StringVar()


frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))


ttk.Label(frame, text="Password Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
length_entry = ttk.Entry(frame, textvariable=length_var, width=5)
length_entry.grid(row=0, column=1, sticky=tk.W)

uppercase_check = ttk.Checkbutton(frame, text="Include Uppercase Letters", variable=uppercase_var)
uppercase_check.grid(row=1, column=0, columnspan=2, sticky=tk.W)

numbers_check = ttk.Checkbutton(frame, text="Include Numbers", variable=numbers_var)
numbers_check.grid(row=2, column=0, columnspan=2, sticky=tk.W)

symbols_check = ttk.Checkbutton(frame, text="Include Symbols", variable=symbols_var)
symbols_check.grid(row=3, column=0, columnspan=2, sticky=tk.W)


generate_button = ttk.Button(frame, text="Generate Password", command=generate_password)
generate_button.grid(row=4, column=0, columnspan=2, pady=10)

password_entry = ttk.Entry(frame, textvariable=password_output, state="readonly", width=30)
password_entry.grid(row=5, column=0, columnspan=2, pady=5)

copy_button = ttk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=6, column=0, columnspan=2, pady=10)


root.mainloop()
