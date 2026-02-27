from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# This line fixes Screenshot 19
app.secret_key = 'sign-vision-secure-key'
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)


# ADD THIS LINE BELOW
app.secret_key = 'super-secret-key-123'


# Initialize the database file
def init_db():
    with sqlite3.connect('messages.db') as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, message TEXT)')

@app.route('/')
def home():
    # Check if 'username' exists in the session
    username = session.get('username') 
    return render_template('index.html', username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        with sqlite3.connect('messages.db') as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user and check_password_hash(user[3], password):
            # NEW: Store user info in the session
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('home')) # Redirect to the home page instead of showing text
        else:
            return "<h1>Login Failed</h1><p>Invalid credentials.</p>"

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_pw = generate_password_hash(password)
        
        try:
            with sqlite3.connect('messages.db') as conn:
                conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                             (username, email, hashed_pw))
            
            # --- CHANGE STARTS HERE ---
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for('login')) 
            # --- CHANGE ENDS HERE ---
            
        except sqlite3.IntegrityError:
            # --- CHANGE STARTS HERE ---
            flash("Email already exists. Try a different one.", "danger")
            return redirect(url_for('signup'))
            # --- CHANGE ENDS HERE ---
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear() # This "forgets" the user
    return redirect(url_for('home'))

@app.route('/contact', methods=['POST'])
def contact():
    name = request.form.get('name')
    email = request.form.get('email')
    msg = request.form.get('message')
    
    with sqlite3.connect('messages.db') as conn:
        conn.execute('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)', (name, email, msg))
    
    return "<h1>Success!</h1><p>Message saved to database.</p><a href='/'>Back Home</a>"

# NEW: Admin route to view messages
@app.route('/admin-view')
def view_messages():
    with sqlite3.connect('messages.db') as conn:
        data = conn.execute('SELECT * FROM contacts').fetchall()
    return f"<h3>All Messages:</h3><p>{str(data)}</p>"


if __name__ == '__main__':
    def init_db():
        # This line MUST be indented by 4 spaces or 1 Tab
        with sqlite3.connect('messages.db') as conn:
            # These lines MUST be indented even further
            conn.execute('''CREATE TABLE IF NOT EXISTS contacts 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             name TEXT, email TEXT, message TEXT)''')
            
            conn.execute('''CREATE TABLE IF NOT EXISTS users 
                            (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                             username TEXT UNIQUE, 
                             email TEXT UNIQUE, 
                             password TEXT)''')
        print("Database Initialized!")

    init_db()
    app.run(debug=True)