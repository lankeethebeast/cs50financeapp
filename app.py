import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session,url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd
from datetime import datetime


# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Add this to your Flask app

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

stocks_data = {
    'AAPL': 150.0,
    'GOOGL': 2500.0,
    'MSFT': 300.0,
}


def get_or_create_stock(stock_symbol, current_price):
    """Get or create a stock entry in the database."""
    # Check if the stock already exists in the database
    existing_stock = db.execute("SELECT id FROM stocks WHERE stock_symbol = ?", stock_symbol)

    if existing_stock:
        # If the stock exists, return its ID
        return existing_stock[0]["id"]
    else:
        # If the stock doesn't exist, create a new entry
        new_stock_id = db.execute(
            "INSERT INTO stocks (stock_symbol, current_price) VALUES (?, ?)",
            stock_symbol, current_price
        )

        # Return the ID of the newly created stock
        return new_stock_id



def get_user_stocks(user_id, stock_symbol):
    """Fetch user's stock details for a specific stock."""
    user_stocks = db.execute(
        "SELECT * FROM user_stocks "
        "JOIN stocks ON user_stocks.stock_id = stocks.id "
        "WHERE user_stocks.user_id = ? AND stocks.stock_symbol = ?",
        user_id, stock_symbol
    )
    return user_stocks[0] if user_stocks else None



def get_user_balance(user_id):
    """Fetch user's cash balance from the database."""
    balance_query = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    return balance_query[0]["cash"] if balance_query else 0.0

@login_required
def get_user_portfolio(user_id):
    """Fetch user's portfolio from the database."""
    portfolio = db.execute(
        "SELECT stocks.stock_symbol, user_stocks.shares, stocks.current_price "
        "FROM user_stocks "
        "JOIN stocks ON user_stocks.stock_id = stocks.id "
        "WHERE user_stocks.user_id = ?",
        user_id
    )
    for stock in portfolio:
        # Calculate total value for each stock
        stock['total_value'] = stock['shares'] * stock['current_price']
    return portfolio

@app.template_filter("usd")
def usd_format(value):
    return "${:,.2f}".format(value)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if 'user_id' not in session:
        # Redirect to login if not logged in
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Get user portfolio and balance from the database
    portfolio = get_user_portfolio(user_id)
    balance = get_user_balance(user_id)
    total_stock_value = sum(stock['total_value'] for stock in portfolio)
    grand_total = balance + total_stock_value

    return render_template('index.html', portfolio=portfolio, balance=balance, grand_total=grand_total)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")  # Display the form to buy stocks

    elif request.method == "POST":
        try:
            user_id = session["user_id"]
            stock_symbol = request.form.get("symbol").upper()
            shares_to_buy = int(request.form.get("shares"))

            # Validate input
            if not stock_symbol or shares_to_buy <= 0:
                return apology("Invalid input", 400)

            # Look up the current price of the stock
            stock_price = lookup(stock_symbol)
            if not stock_price:
                return apology("Stock symbol not found", 400)

            total_cost = stock_price["price"] * shares_to_buy

            # Check if the user has enough cash to buy the stocks
            user_balance = get_user_balance(user_id)
            if total_cost > user_balance:
                return apology("Not enough cash to buy", 400)

            # Update user's cash balance
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, user_id)

            # Check if the user already owns shares of this stock
            user_stock = get_user_stocks(user_id, stock_symbol)
            if user_stock:
                # Update existing user_stock
                db.execute(
                    "UPDATE user_stocks SET shares = shares + ? WHERE user_id = ? AND stock_id = ?",
                    shares_to_buy, user_id, user_stock["stock_id"]
                )
            else:
                # Insert new user_stock
                stock_id = get_or_create_stock(stock_symbol, stock_price["price"])
                db.execute(
                    "INSERT INTO user_stocks (user_id, stock_id, shares) VALUES (?, ?, ?)",
                    user_id, stock_id, shares_to_buy
                )

            # Log the transaction
            db.execute(
                "INSERT INTO transactions (user_id, stock_symbol, shares, price, transaction_type, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                user_id, stock_symbol, shares_to_buy, stock_price["price"], "BUY", datetime.now()
            )

            flash(f"Successfully bought {shares_to_buy} shares of {stock_symbol}")
            return redirect(url_for("index"))

        except Exception as e:
            print(f"Exception: {e}")
            return apology("An error occurred during the buy operation", 500)

    return apology("Invalid request method", 400)




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]

    # Fetch transaction history for the user from the database
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        user_id
    )
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == 'GET':
        return render_template('quote.html')
    elif request.method == 'POST':
        symbol = request.form.get('symbol').upper()

        if symbol in stocks_data:
            price = stocks_data[symbol]
            return render_template('quoted.html', symbol=symbol, price=price)
        else:
            error_message = f"Symbol '{symbol}' not found."
            return render_template('quote.html', error=error_message)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':
        try:

            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            # Validate input
            if not username or not password or not confirm_password:
                return apology('PLEASE INSERT USERNAME AND PASSWORD', 403)

            if password != confirm_password:
                return apology('CHECK IF PASSWORD MATCHES',403)

            # Check if username already exists
            existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,))

            if len(existing_user) > 0:
                return apology('Username already exists', 403)

            # Hash the password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha512')
            # Insert user into the database
            db.execute('INSERT INTO users (username, hash) VALUES (?)', (username, hashed_password))
            db

            return redirect(url_for('login'))

        except Exception as e:
            print(f"Exception: {e}")
            return apology("An error occurred during registration", 500)


    return render_template('registration.html')



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        # Get the list of stocks that the user currently owns
        user_id = session["user_id"]
        stocks_owned = get_user_portfolio(user_id)

        # Render the sell page with the list of stocks owned
        return render_template("sell.html", stocks_owned=stocks_owned)

    elif request.method == "POST":
        try:
            # Extract form data
            user_id = session["user_id"]
            stock_symbol = request.form.get("symbol")
            shares_to_sell = int(request.form.get("shares"))

            # Validate input
            if not stock_symbol or shares_to_sell <= 0:
                return apology("Invalid input", 400)

            # Check if the user owns enough shares to sell
            user_stock = get_user_stocks(user_id, stock_symbol)
            if not user_stock or user_stock["shares"] < shares_to_sell:
                return apology("Not enough shares to sell", 400)

            # Get the current price of the stock
            stock_price = stocks_data.get(stock_symbol)
            if stock_price is None:
                return apology("Stock symbol not found", 400)

            # Calculate the total value of the sold shares
            total_value = stock_price * shares_to_sell

            # Update the user's balance
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_value, user_id)

            # Update the user's stock portfolio
            db.execute(
                "UPDATE user_stocks SET shares = shares - ? WHERE user_id = ? AND stock_id = ?",
                shares_to_sell, user_id, user_stock["stock_id"]
            )

            # If all shares have been sold, remove the stock from the portfolio
            remaining_shares = user_stock["shares"] - shares_to_sell
            if remaining_shares <= 0:
                db.execute(
                    "DELETE FROM user_stocks WHERE user_id = ? AND stock_id = ?",
                    user_id, user_stock["stock_id"]
                )

            # Log the sell transaction
            db.execute(
                "INSERT INTO transactions (user_id, stock_symbol, shares, price, transaction_type, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                user_id, stock_symbol, -shares_to_sell, stock_price, "SELL", datetime.now()
            )

            flash("Successfully sold {} shares of {}".format(shares_to_sell, stock_symbol))
            return redirect(url_for("index"))

        except Exception as e:
            print(f"Exception: {e}")
            return apology("An error occurred during the sell operation", 500)

    return apology("Invalid request method", 400)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        user_id = session["user_id"]
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_new_password")

        # Validate input
        if not current_password or not new_password or not confirm_new_password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("account"))

        # Retrieve the user's current hashed password from the database
        # Assuming db.execute returns a list of rows
        user = db.execute("SELECT * FROM users WHERE id = ?", user_id)

        # Check if user is not None before accessing its elements
        if user:
            user = user[0]
            hashed_password = user["hash"]
        else:
            # Handle the case where the user with the specified ID is not found
            flash("User not found.", "error")
            return redirect(url_for("account"))



        # Verify the current password
        if not check_password_hash(hashed_password, current_password):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("account"))

        # Check if the new password and confirmation match
        if new_password != confirm_new_password:
            flash("New password and confirmation do not match.", "error")
            return redirect(url_for("account"))

        # Hash the new password and update it in the database
        new_hashed_password = generate_password_hash(new_password, method="pbkdf2:sha512")
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hashed_password, user_id)
        db

        flash("Password successfully changed.", "success")
        return redirect(url_for("account"))

    return render_template("account.html")
