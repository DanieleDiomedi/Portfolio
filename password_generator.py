#!/usr/bin/env python3
import string
import random
def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    characters = ''
    
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("Nessun set di caratteri selezionato")

    password = ''.join(random.choice(characters) for _ in range(length))
    return password
if __name__ == "__main__":
    try:
        length = int(input("Lunghezza password: "))
        use_upper = input("Maiuscole? (y/n): ").lower() == 'y'
        use_lower = input("Minuscole? (y/n): ").lower() == 'y'
        use_digits = input("Numeri? (y/n): ").lower() == 'y'
        use_symbols = input("Simboli? (y/n): ").lower() == 'y'

        pwd = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
        print("\nPassword generata:", pwd)
    except Exception as e:
        print("Errore:", e)

