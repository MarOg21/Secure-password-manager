import sqlite3


DATABASE_NAME = "database.db" #names the DB file.


def get_db_connection(): #This fucntion establishes a connection to the SQLite.
    connection = sqlite3.connect(DATABASE_NAME)
    # Allows database rows to be accessed by column name.
    connection.row_factory = sqlite3.Row
    # Enables foreign-key protection in SQLite.
    connection.execute("PRAGMA foreign_keys = ON") #enables foreign key protection in SQLite.
    return connection


def init_db(): #this creates the DB tables.
    with get_db_connection() as connection:
        cursor = connection.cursor() 

        # Stores registered users.
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            encryption_key BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """) # creates a table that stores users with their username, hashed password, encryption key, and the time they were created.

        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS information (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site TEXT NOT NULL,
            site_username BLOB NOT NULL,
            site_password BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        """) # creates a table that stores the credentials of each user.

        connection.commit() 