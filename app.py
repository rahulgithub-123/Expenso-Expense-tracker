import bcrypt
from flask import Flask, render_template, request, redirect, session, url_for, flash
import mysql.connector
import datetime
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',  
        user='root',       
        password='',  
        database='expense_track_db' 
    )

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not username or not password or not email:
            msg = 'Please fill out the form!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        else:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute('SELECT * FROM user WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists!'
            else:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                cursor.execute('INSERT INTO user (username, password, email) VALUES (%s, %s, %s)', 
                               (username, hashed_password, email))
                connection.commit()
                msg = 'You have successfully registered!'

    return render_template('index.html', msg=msg)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account:
            if bcrypt.checkpw(password.encode('utf-8'), account['password'].encode('utf-8')):
                session['user_email'] = account['email']  
                msg = 'Logged in successfully!'
                return redirect(url_for('home'))  
            else:
                msg = 'Incorrect password!'
        else:
            msg = 'No account found with that email address!'

    return render_template('index.html', msg=msg)


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))  
    
    user_email = session['user_email']  

    date_filter = request.args.get('date_filter')
    amount_filter = request.args.get('amount_filter')

    conditions = []
    params = [user_email]  

    if date_filter:
        conditions.append("DATE(createdAt) = %s")
        params.append(date_filter)
    
    if amount_filter:
        if amount_filter == "under_100":
            conditions.append("amount < 100")
        elif amount_filter == "under_200":
            conditions.append("amount < 200")
        elif amount_filter == "under_300":
            conditions.append("amount < 300")
        elif amount_filter == "under_400":
            conditions.append("amount < 400")
        elif amount_filter == "under_500":
            conditions.append("amount < 500")
        elif amount_filter == "under_1000":
            conditions.append("amount < 1000")
        elif amount_filter == "under_2000":
            conditions.append("amount < 2000")
        elif amount_filter == "under_5000":
            conditions.append("amount < 5000")

    query = "SELECT * FROM expense WHERE user_email = %s" 

    if conditions:
        query += " AND " + " AND ".join(conditions)

    query += " ORDER BY createdAt DESC"

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute(query, tuple(params))  
    expenses = cursor.fetchall()

    return render_template('dashboard.html', expenses=expenses, date_filter=date_filter, amount_filter=amount_filter)

@app.route('/expense', methods=['GET', 'POST'])
def add_expense():
    if 'user_email' not in session:
        return redirect(url_for('login'))  

    if request.method == 'POST':
        amount = request.form['amount']
        category = request.form['category']
        description = request.form['Description']
        user_email = session['user_email']  

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO expense (amount, category, description, createdAt, user_email)
            VALUES (%s, %s, %s, %s, %s)
        """, (amount, category, description, datetime.datetime.now(), user_email))  
        connection.commit()
        flash("Expense added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_expense.html')

@app.route('/budget', methods=['GET', 'POST'])
def budget():
    if 'user_email' not in session:
        return redirect(url_for('login'))  

    if request.method == 'POST':
        amount = request.form['amount']
        category = request.form['category']
        user_email = session['user_email']  

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO budget (amount, category, user_email)
            VALUES (%s, %s, %s)
        """, (amount, category, user_email))  
        connection.commit()
        flash("Budget added successfully!", "success")
        return redirect(url_for('viewbudget'))

    return render_template('budget.html')

@app.route('/viewbudget', methods=['GET', 'POST'])
def viewbudget():
    if 'user_email' not in session:
        return redirect(url_for('login'))  
    
    user_email = session['user_email']  
    
    query = "SELECT * FROM budget WHERE user_email = %s ORDER BY createdAt DESC"
    params = [user_email]  # parameters to pass to the query

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(query, tuple(params))

    budget_entries = cursor.fetchall()
    return render_template('viewbudget.html', budget_entries=budget_entries)


@app.route('/logout')
def logout():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=3000)