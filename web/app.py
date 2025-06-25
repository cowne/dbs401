from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import requests
import os

app = Flask(__name__)
app.secret_key = 'Str@ngS3c3rtK3y'  
PROXY_URL = os.getenv("PROXY_URL", "http://localhost:8000/check_and_run")

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

        query = 'SELECT * FROM users WHERE username="' + username + '" AND password ="'+ password +'"'
        # query = "SELECT * FROM users WHERE username='" + username + "' AND password = '" + password + "'"
        response = requests.post(PROXY_URL, json={"query": query})
        if response.status_code == 403:
            return render_template('Attackdetection.html')
        elif response.status_code == 200:
            session['logged_in'] = True
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
    name_product = ""
    if request.method == 'POST':
        name_product = request.form['name']
        query = "SELECT * FROM product WHERE name_product LIKE '%" + name_product +"%'"
        response = requests.post(PROXY_URL, json={"query": query})
        if response.status_code == 403:
            return render_template('Attackdetection.html')
        elif response.status_code == 200:
            results = response.json().get("result", [])
            return render_template('search.html', name_product=name_product, results=results)
        else:
            flash("No result for the product. Please try again.", "info")
            return redirect(url_for('search'))
    return render_template('search.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
