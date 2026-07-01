import os
from dotenv import load_dotenv

load_dotenv() #loads variables from .env file into the environment, making them accessible via os.environ.get().

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") #loads the flask secret key from .env file.
    SESSION_COOKIE_HTTPONLY = True # This prevents java script from accessing the session cookie.
    SESSION_COOKIE_SAMESITE = "Lax" # This helps protect against CSRF attacks by ensuring that the session cookie is only sent in a first-party context.


    SESSION_COOKIE_SECURE = False # set to flase for loacl development.

    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY is not found from the environment variables.")