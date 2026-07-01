# handles all security-related functions, including encryption, decryption, and password generation.

import secrets # used for creating secure random passwords.
import string 

from cryptography.fernet import Fernet, InvalidToken # used for symmetric encryption and decryption of user data.


# Possible characters for generated passwords.
PASSWORD_CHARACTERS = (string.ascii_letters + string.digits + "!@#$%^&*()-_=+")


def create_encryption_key_for_user():
	"""Generates a unique Fernet encryption key for a new user.""" #creates a unique encryption key for every new user.

	return Fernet.generate_key()


def encrypt_value(value, encryption_key):
	"""Encrypts a text value using the user's encryption key."""

	fernet = Fernet(encryption_key)

	encrypted_value = fernet.encrypt(value.encode("utf-8")) # converts normal texts into encrypted bytes.

	return encrypted_value


def decrypt_value(encrypted_value, encryption_key):
	"""Decrypts an encrypted value using the user's encryption key."""

	fernet = Fernet(encryption_key)

	try:
		decrypted_value = fernet.decrypt(encrypted_value).decode("utf-8") #converts encrypted bytes back into normal text.
		return decrypted_value
	except InvalidToken:
		return "[Unable to decrypt]"


def generate_secure_password(length=16):
	"""Creates a secure random password.""" #creates a sceure password.

	if length < 12:
		raise ValueError("Try Again! Password length must be at least 12 characters long.")

	password = "".join(secrets.choice(PASSWORD_CHARACTERS) for _ in range(length))

	return password