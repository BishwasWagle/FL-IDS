from flask import Flask, request, render_template, redirect, url_for, session
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="0000",
    database="ids"
)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    cursor = db.cursor(dictionary=True)
    
    # 🔥🔥 VULNERABLE CODE 🔥🔥
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing query: {query}")  # Debugging output
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        session['user'] = user['username']
        return redirect(url_for('dashboard'))
    else:
        return "Invalid username or password", 401

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome, {session['user']}!"
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
