#flask application

from flask import (
Flask,
render_template,
request,
redirect,
session,
url_for,
flash
)

from flask_wtf.csrf import CSRFProtect #prevents cross site request forgery attacks.
from flask_limiter import Limiter # reduces brute-force login attempts and protects against abuse.
from flask_limiter.util import get_remote_address

from werkzeug.security import (generate_password_hash, check_password_hash) #hashes passwords securely and verifies them during login.

from config import Config #loads configuration file for the application where the secret keys are defined.
from database import get_db_connection, init_db #properly handles database connections and initializes the database schema.

from security import (create_encryption_key_for_user, encrypt_value, decrypt_value, generate_secure_password) #takes care of the encryption and decryption of user credentials.


app = Flask(__name__)# This creates the Flask application.
app.config.from_object(Config) #loads setting from confuguration file.

csrf = CSRFProtect(app) #actvitaves CSRF protection for all forms in the application.

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]) #sets a limit on how many requests a user can send per day and per hour.




#Home page

@app.route("/")
def index():
    if 'user_id' in session:#redirects user to dashboard if they are already logged in.
        return redirect(url_for('dashboard'))
    return render_template("index.html")





#User registration

@app.route("/register", methods=["GET", "POST"]) #handles both displaying the registration form and processing the form submission when a user tries to register. depends on the request method. 

def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3: #checks if the user name is short.
            flash("Username is too short. must be at least 3 characters.")
            return render_template("register.html")

        if len(password) < 12:
            flash("Password is too short. must be at least 12 characters.") # checks if the password is short.
            return render_template("register.html")

        hashed_password = generate_password_hash(password) #hashes the password before storing to further enhance security.
        encryption_key = create_encryption_key_for_user() # creates a unique encryption key for the user to encrypt/decrypt their credentials.

        try:
            with get_db_connection() as connection:
                connection.execute(""" INSERT INTO users (username, password, encryption_key) VALUES (?, ?, ?) """,
                    (username, hashed_password, encryption_key),
                ) # this inserts users into database.
                connection.commit()
        except Exception:
            flash("Username is already taken.")
            return render_template("register.html")

        flash("You have been registered. you can now log in.") # checks for duplicate username because the DB needs unique usernames.
        return redirect(url_for("login"))

    return render_template("register.html")




#login page

@app.route("/login", methods=["GET", "POST"]) #handles both displaying the login form and processing the form submission when a user tries to log in. depends on the request method.
@limiter.limit("5 per minute") # sets a number to how many login attempts a user can make per minute.
def login():
    if request.method == "POST": # processes the login form submission. It retrieves the username and password from the form, checks if the user exists in the database, and verifies the password using check_password_hash. If the credentials are valid, it creates a session for the user and redirects them to the dashboard. If not, it flashes an error message.
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db_connection() as connection:
            user = connection.execute(
                """
                SELECT id, password
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone() #checks if the user exists in the data base.

        if user and check_password_hash(user["password"], password): #checks if the password matches the stored hash.
            session.clear() #clears any old session.
            session["user_id"] = user["id"] #stores the user's ID in the session to keep them logged in.
            return redirect(url_for("dashboard")) #redirects the user to the dashboard if login is successful.

        flash("Error! Invalid username or password.")

    return render_template("login.html")





#User dashboard

@app.route("/dashboard") # shows logged in users ctedentials.
def dashboard():
    if "user_id" not in session: #prevents unauthorized access to the dashboard by checking if the user is logged in. 
        return redirect(url_for("login"))

    user_id = session["user_id"] # gets the logged in user id.

    with get_db_connection() as connection:
        user = connection.execute(
            """
            SELECT encryption_key FROM users WHERE id = ? """, #gets the users encryption key.
            (user_id,),
        ).fetchone()

        if not user:
            session.clear() # redircts to login if the user is not found in the database.
            return redirect(url_for("login"))

        rows = connection.execute(
            """
            SELECT
                id,
                site,
                site_username,
                site_password
            FROM information
            WHERE user_id = ?
            ORDER BY created_at DESC
            """, #gets the credentials for the logged in user.
            (user_id,),
        ).fetchall()

    encryption_key = user["encryption_key"] #stores the encryption key in a variable for later use in decrypting the credentials.
    credentials = [] #decrypts the credentials retrieved from the database and prepares them for display on the dashboard. It iterates through each row of credentials, decrypts the site username and password using the user's encryption key, and appends the decrypted credentials to a list that will be passed to the template for rendering.

    for row in rows:
        credentials.append({
            "id": row["id"],
            "site": row["site"],
            "username": decrypt_value(
                row["site_username"],
                encryption_key,
            ),
            "password": decrypt_value(
                row["site_password"],
                encryption_key,
            ),
        }) #the stored credentials are decrypted before being shown on the dashboard.

    return render_template(
        "dashboard.html",
        credentials=credentials,
    )



#add encrypted credentials
#permits the logged in user to add new credentials to their vault.

@app.route("/add", methods=["GET", "POST"])
def add_credentials():
        if "user_id" not in session: #prevents unauthorized access to the add credentials page by checking if the user is logged in. If not, it redirects them to the login page.
            return redirect(url_for("login"))

        if request.method == "POST": #processes the form submission when a user tries to add new credentials. It collects the site, site username, and site password from the form, checks if all fields are completed, and if so, it encrypts the site username and password using the user's encryption key before storing them in the database. If any field is missing.
            site = request.form.get("site", "").strip()

            site_username = request.form.get("site_username", "").strip()

            site_password = request.form.get("site_password", "")

            if not site or not site_username or not site_password: #check if any field is incomplete.
                flash("Error! Please complete required fields.")
                return render_template("add_credentials.html")
            
            with get_db_connection() as connection:
                user = connection.execute(""" SELECT encryption_key FROM users WHERE id = ? """, (
                    session["user_id"],
                )).fetchone() #retrieves the user's encryption key from the database to encrypt the new credentials before storing them. If the user is not found, it clears the session and redirects to the login page.

           
                if not user:
                    session.clear()
                    return redirect(url_for("login"))

                encrypted_username = encrypt_value(
                    site_username,
                    user["encryption_key"] #username is encrypted before being stored in the database.
                )

                encrypted_password = encrypt_value(
                    site_password,
                    user["encryption_key"] #password is encrypted before beimg stored.
                )

                connection.execute(""" INSERT INTO information ( user_id, site, site_username, site_password)
VALUES (?, ?, ?, ?)
""", (
                    session["user_id"],
                    site,
                    encrypted_username,
                    encrypted_password
                ))

                connection.commit()

            return redirect(url_for("dashboard"))

        return render_template("add_credentials.html")
    



#edit credentials
# allows users to edit their stored credentials.

@app.route("/edit/<int:credential_id>", methods=["GET", "POST"]) #handles both displaying the edit form and processing the form submission when a user tries to edit an existing credential. 
def edit_credential(credential_id):
    if "user_id" not in session: #prevents unauthorized access to the edit credential page by checking if the user is logged in. If not, it redirects them to the login page.
        return redirect(url_for("login"))

    user_id = session["user_id"] #gets the logged in user.

    with get_db_connection() as connection:
        user = connection.execute("""
SELECT encryption_key FROM users WHERE id = ? """, (user_id,)).fetchone() # this checks both the credential id and the user id to ensure that users can only edit their own credentials. 

        credential = connection.execute("""
SELECT
id,
site,
site_username,
site_password
FROM information
WHERE id = ? AND user_id = ?
""", (
            credential_id,
            user_id
        )).fetchone()

        if not user or not credential: # checks if the user or credential exits in the DB.
            return "Invalid credential", 404

        encryption_key = user["encryption_key"]

        if request.method == "POST":
            site = request.form.get(
                "site", ""
            ).strip()

            username = request.form.get(
                "site_username", ""
            ).strip()

            password = request.form.get(
                "site_password", ""
            ) #after form has been submitted, the updated details are then encrypted again before storing

            if not site or not username or not password:
                flash("Error! Please complete required fields.")
                return redirect(
                    url_for(
                        "edit_credential",
                        credential_id=credential_id
                    )
                )

            encrypted_username = encrypt_value(
                username,
                encryption_key
            )

            encrypted_password = encrypt_value(
                password,
                encryption_key
            )

            connection.execute("""
UPDATE information
SET
site = ?,
site_username = ?,
site_password = ?
WHERE id = ? AND user_id = ? 
""", (  site,
        encrypted_username,
        encrypted_password,
        credential_id,
        user_id
            )) #updates the credentials securely.

            connection.commit()

            return redirect(url_for("dashboard"))

        decrypted_username = decrypt_value(
            credential["site_username"],
            encryption_key
        )

        decrypted_password = decrypt_value(
            credential["site_password"],
            encryption_key
        )

        return render_template(
            "edit_credential.html",
            credential_id=credential_id,
            site=credential["site"],
            username=decrypted_username,
            password=decrypted_password)



#delete credentials
# allows users to delete their stored credentials.

@app.route("/delete/<int:credential_id>", methods=["POST"]) #uses post method because it performs a delete action which makes changes in the database.
def delete_credential(credential_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as connection:
        connection.execute("""
            DELETE FROM information
            WHERE id = ? AND user_id = ?
        """, (
            credential_id,
            session["user_id"]
        )) #delets the credential which only belongs to a logged in user.
        connection.commit()

    return redirect(url_for("dashboard"))



#password generator
#provides a random secure password.

@app.route("/generate")
def generate_password():
    if "user_id" not in session:
        return redirect(url_for("login"))

    password = generate_secure_password(16) # from the fucntion in security.py, it uses the secret modeule to generate a strong password.
    return render_template(
        "generate_password.html",
        password=password
    )


#User logout
#logs users out by clearing the existing session.

@app.route("/logout", methods=["POST"]) #uses POST method because logout changes the user's sesssion state.
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__": #runs the applocation iff app.py is executed directly.
    init_db() #This creats the DB tables if they do not exist before the application starts.
    app.run(debug=False) #runs the application in production mode with debug mode turned off for security reasons.

    

