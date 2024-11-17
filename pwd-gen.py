import secrets
import string


def is_pwd_strong(password, use_uppercase, use_numbers, use_symbols):
    has_uppercase = any(char.isupper() for char in password) if use_uppercase else True
    has_numbers = any(char.isdigit() for char in password) if use_numbers else True
    has_symbols = any(char in string.punctuation for char in password) if use_symbols else True
    return len(password) >= 8 and has_uppercase and has_numbers and has_symbols


def gen_pwd(length, use_uppercase, use_numbers, use_symbols):
    
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ""
    numbers = string.digits if use_numbers else ""
    symbols = string.punctuation if use_symbols else ""
    all_characters = lowercase + uppercase + numbers + symbols

    
    if not all_characters:
        raise ValueError("At least one character type must be selected.")

    
    while True:
        password = ''.join(secrets.choice(all_characters) for _ in range(length))
        if is_pwd_strong(password, use_uppercase, use_numbers, use_symbols):
            return password


def main():
    print("Password Generator: ")
    try:
        
        length = int(input("Enter password length (Minimum characters = 8): "))
        if length < 8:
            print("Password length is too short. Setting to minimum of 8 characters.")
            length = 8

        
        use_uppercase = input("Include uppercase letters? (Y/N): ").strip().lower() == "y"
        use_numbers = input("Include numbers? (Y/N): ").strip().lower() == "y"
        use_symbols = input("Include symbols? (Y/N): ").strip().lower() == "y"

        
        password = gen_pwd(length, use_uppercase, use_numbers, use_symbols)
        print("Password generated:", password)
    except ValueError as e:
        print("Error:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)


if __name__ == "__main__":
    main()
