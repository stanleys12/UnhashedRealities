from flask import Flask, render_template_string, request, redirect, url_for, flash
import bcrypt
import hashlib
import subprocess
import time

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
        input[type="text"], input[type="password"] {
            padding: 10px;
            font-size: 14px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        input[type="submit"] {
            padding: 10px;
            background: #4CAF50;
            border: none;
            color: white;
            font-weight: bold;
            border-radius: 5px;
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
        password_bytes = password.encode('utf-8')

        if username in users:
            flash("Username already exists.")
            return redirect(url_for('register'))

        # Hash with bcrypt
        salt = bcrypt.gensalt()
        hashed_bcrypt = bcrypt.hashpw(password_bytes, salt)
        users[username] = hashed_bcrypt

        # Also create an MD5 hash to test cracking
        md5_hash = hashlib.md5(password_bytes).hexdigest()
        with open('hashes.txt', 'w') as f:
            f.write(md5_hash + '\n')

        # Try running Hashcat on the hash with a wordlist
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
                flash("Password not found in dictionary (rockyou.txt).")

        except Exception as e:
            flash(f"Error running Hashcat: {e}")

        flash("Registered successfully!")
        return redirect(url_for('register'))

    return render_template_string(HTML_TEMPLATE)

if __name__ == "__main__":
    app.run(debug=True)
