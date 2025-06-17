from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from proxy import check_exploit_sqli

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key in production

# Dummy user (replace with database in real app)
USER_CREDENTIALS = {
    'username': 'admin',
    'password': 'password123'
}

# Dummy search data
ITEMS = ["apple", "banana", "grape", "orange", "pineapple", "strawberry"]

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash("You must be logged in to view that page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        query = "SELECT username,password FROM users WHERE username='" + username + "' AND password ='"+ password +"'"
        
        if(check_exploit_sqli(query)):
            return render_template('Attackdetection.html')
        else:
            return redirect(url_for('search'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    query = ""
    results = []
    if request.method == 'POST':
        query = request.form['query']
        results = [item for item in ITEMS if query.lower() in item.lower()]
    return render_template('search.html', query=query, results=results)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
