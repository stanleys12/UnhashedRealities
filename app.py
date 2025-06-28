from flask import Flask, render_template_string, request, redirect, url_for, flash
import bcrypt
import hashlib
import subprocess
import time
from argon2 import PasswordHasher

ph = PasswordHasher()

app = Flask(__name__)
app.secret_key = "supersecretkey"
users = {}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Unhashed Realities</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            padding: 40px;
        }
        .container {
            max-width: 600px;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin: auto;
        }
        h1, h2 {
            text-align: center;
            color: #333;
        }
        .flash {
            background-color: #e0f7e9;
            border-left: 5px solid #4CAF50;
            padding: 10px;
            margin-bottom: 10px;
        }
        form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        input, select {
            padding: 10px;
            font-size: 14px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        input[type="submit"] {
            background: #4CAF50;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }
        a {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #4CAF50;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Unhashed Realities</h1>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="flash">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <h2>Register</h2>
        <form method="POST" action="/register">
            <label>Username:</label>
            <input type="text" name="username" required>
            <label>Password:</label>
            <input type="password" name="password" required>
            <label>Choose Hashing Algorithm:</label>
            <select name="algorithm" required>
                <option value="bcrypt">Bcrypt</option>
                <option value="md5">MD5</option>
                <option value="sha1">SHA-1</option>
                <option value="sha256">SHA-256</option>
                <option value="argon2">Argon2</option>
            </select>
            <input type="submit" value="Register">
        </form>
        <a href="/">Back to Home</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return '''
        <h1>Welcome to Unhashed Realities</h1>
        <p><a href="/register">Register</a></p>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        algorithm = request.form['algorithm']
        password_bytes = password.encode('utf-8')

        if username in users:
            flash("Username already exists.")
            return redirect(url_for('register'))

        if algorithm == "bcrypt":
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password_bytes, salt).decode()
        elif algorithm == "md5":
            hashed = hashlib.md5(password_bytes).hexdigest()
        elif algorithm == "sha1":
            hashed = hashlib.sha1(password_bytes).hexdigest()
        elif algorithm == "sha256":
            hashed = hashlib.sha256(password_bytes).hexdigest()
        elif algorithm == "argon2":
            hashed = ph.hash(password)

        users[username] = {"hash": hashed, "algorithm": algorithm}

        if algorithm == "md5":
            with open('hashes.txt', 'w') as f:
                f.write(hashed + '\n')
            try:
                start_time = time.time()
                result = subprocess.run(
                    ['hashcat', '-a', '0', '-m', '0', 'hashes.txt', '/Users/stanleyshen/Unhashed_pass/rockyou.txt', '--quiet', '--show'],
                    capture_output=True,
                    text=True
                )
                duration = time.time() - start_time
                if result.stdout.strip():
                    flash(f"Password cracked in {duration:.2f} seconds using dictionary attack.")
                else:
                    flash("Password not found in rockyou.txt.")
            except Exception as e:
                flash(f"Error running Hashcat: {e}")

        flash(f"Password hashed using {algorithm.upper()} successfully!")
        return redirect(url_for('register'))

    return render_template_string(HTML_TEMPLATE)

if __name__ == "__main__":
    app.run(debug=True)
