import os

from bleach import clean
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from re import match
from tempfile import mkdtemp
from time import sleep
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":

        # Get the amount of cash the user wants to add
        cash = request.form.get("cash")

        # Sanitize the cash input
        cash = clean(cash)

        # Validate the input
        if not cash:
            return apology("Please enter an amount of cash.")

        try:
            cash_float = float(cash)
        except ValueError:
            return apology("Please enter a valid amount of cash.")
        if cash_float <= 0:
            return apology("Please enter a positive amount of cash.")
        else:
            cash = cash_float

        # Add the cash to the user's account
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cash_float, session["user_id"])

        # Redirect the user to the index page
        return redirect("/")

    else:
        return render_template("add_cash.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy(symbol=None, shares=None):
    """Buy shares of stock"""

    if request.method == "POST":

        # Get the symbol if it didn't come from the index page
        if symbol == None:
            symbol = request.form.get("symbol").upper().strip()

        # Get the shares input if it didn't come from the index page
        if shares == None:
            shares = request.form.get("shares").strip()

        # Sanitize variables
        symbol = clean(symbol)
        shares = clean(shares)

        # Ensure stock's symbol was submitted
        if not symbol:
            return apology("must provide stock's symbol")
        elif lookup(symbol) == None:
            return apology("the inserted symbol doesn't exist")

        # Ensure the amount of shares was submitted
        if not shares:
            return apology("must provide the number of shares")
        try:
            shares_int = int(shares)
        except ValueError:
            return apology("shares should be a positive integer")
        if shares_int <= 0:
            return apology("shares should be a positive integer")
        else:
            shares = shares_int

        # Get the stock's name and price
        price = lookup(symbol)["price"]
        name = lookup(symbol)["name"]

        # Get the user's cash amount
        cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Find the total amount
        total = price * shares

        if total > cash:
            return apology("you don't have enough money")

        # Create transactions table if not exists
        db.execute("CREATE TABLE IF NOT EXISTS transactions (id INTEGER NOT NULL, user_id INTEGER, name TEXT NOT NULL, symbol TEXT NOT NULL, price FLOAT NOT NULL, shares INTEGER NOT NULL, action TEXT NOT NULL, timestamp TIMESTAMP NOT NULL, PRIMARY KEY(id), FOREIGN KEY(user_id) REFERENCES users(id))")

        # Insert the data
        db.execute("INSERT INTO transactions (user_id, name, symbol, price, shares, action, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                   session["user_id"], name, symbol, price, shares, "buy")

        # Update the user's cash
        db.execute("UPDATE users SET cash = (cash - ?) WHERE id = ?", total, session["user_id"])

        flash(f"Bought {shares} share(s) of {name} for {usd(float(total))}")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change the password"""

    if request.method == "POST":

        # Get current and new passwords from the form
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Sanitize variables
        current_password = clean(current_password)
        new_password = clean(new_password)
        confirmation = clean(confirmation)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure current password was submitted
        if not current_password:
            return apology("must provide current password")

        # Ensure current password is correct
        if not check_password_hash(rows[0]["hash"], current_password):
            return apology("invalid current password")

        # Ensure new password was submitted
        if not new_password:
            return apology("must provide new password")
        elif len(new_password) < 8:
            return apology("password must be at least 8 characters long")
        elif not match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$", new_password):
            return apology("password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 digit")

        # Ensure password confirmation matches
        if new_password != confirmation:
            return apology("passwords don't match")

        # Update user's password in database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), session["user_id"])

        # Redirect user to home page
        return redirect("/")

    else:
        # Display the change password form
        return render_template("change_password.html")


def get_stocks(user_id):
    """Returns a determined user's stocks"""

    try:
        db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = 'transactions'")
    except:
        stocks = []
    else:
        stocks = db.execute("""
            SELECT symbol, name, SUM(CASE WHEN action = 'buy' THEN shares ELSE -shares END) AS total_shares
            FROM transactions
            WHERE user_id = ?
            GROUP BY symbol
            HAVING total_shares != 0
        """, user_id)
    return stocks


@app.route("/shares/<symbol>")
@login_required
def get_shares(symbol):
    """Return the number of shares the user owns for a given stock symbol"""

    # Get the user's stocks
    stocks = get_stocks(session["user_id"])

    # Find the stock with the given symbol
    stock = next((s for s in stocks if s["symbol"] == symbol), None)

    # Return the number of shares or 0 if the user does not own any shares of the given stock
    return jsonify({"shares": stock["total_shares"] if stock else 0})


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get the user's transactions
    transactions = db.execute("SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    if request.method == "POST":

        # Get the form info
        transaction = request.form.get("action")
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Sanitize transaction
        transaction = clean(transaction)

        if transaction == "buy":
            return buy(symbol=symbol, shares=shares)
        else:
            return sell(symbol=symbol, shares=shares)

    else:
        # Get the user's cash
        cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Get the user's stocks
        stocks = get_stocks(session["user_id"])

        if len(stocks) > 0:
            # Add the current price of the stock to stocks
            stocks = [{**stock, "current_price": lookup(stock["symbol"])["price"]} for stock in stocks]

            # Calculate the total amount the user has
            total_sum = sum((stock["total_shares"] * stock["current_price"]) for stock in stocks) + cash

        else:
            # No stocks means total_sum equals cash
            total_sum = cash

        return render_template("index.html", stocks=stocks, cash=cash, total_sum=total_sum)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get the form's data
        username = request.form.get("username")
        password = request.form.get("password")

        # Sanitize variables
        username = clean(username)
        password = clean(password)

        # Ensure username was submitted
        if not username:
            return apology("must provide username")

        # Ensure password was submitted
        if not password:
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1:
            return apology("invalid username")
        elif not check_password_hash(rows[0]["hash"], password):
            return apology("invalid password")

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

    if request.method == "POST":

        # Get the symbol
        symbol = request.form.get("symbol").upper()

        # Sanitize symbol
        symbol = clean(symbol)

        # Get the symbol's quote
        quote = lookup(symbol)

        # Ensure stock's symbol was submitted
        if not symbol:
            return apology("must provide stock's symbol")
        elif quote == None:
            return apology("the inserted symbol doesn't exist")

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get the user's data
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Sanitize variables
        username = clean(username)
        password = clean(password)
        confirmation = clean(confirmation)

        # Ensure username was submitted
        if not username:
            return apology("must provide username")
        elif len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            return apology("username is already being used")

        # Ensure password was properly submitted
        if not password:
            return apology("must provide password")
        elif len(password) < 8:
            return apology("password must be at least 8 characters long")
        elif not match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$", password):
            return apology("password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 digit")

        # Ensure the password confirmation was submitted
        if not confirmation:
            return apology("must provide confirmation")

        # Ensure confirmation matches the password
        if password != confirmation:
            return apology("the passwords don't match")

        # Hash the password
        hash = generate_password_hash(password)

        # Insert values into db
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell(symbol=None, shares=None):
    """Sell shares of stock"""

    stocks = get_stocks(session["user_id"])

    if request.method == "POST":

        # Get the symbol if it didn't come from the index page
        if symbol == None:
            symbol = request.form.get("symbol")

        # Get the shares input if it didn't come from the index page
        if shares == None:
            shares = request.form.get("shares")

        # Sanitize variables
        symbol = clean(symbol)
        shares = clean(shares)

        # Ensure stock's symbol was properly submitted
        if not symbol:
            return apology("must provide stock's symbol")
        elif symbol not in [stock['symbol'] for stock in stocks]:
            return apology("you do not own any shares of this stock")

        # Ensure the amount of shares was properly submitted
        if not shares:
            return apology("must provide the number of shares")
        try:
            shares_int = int(shares)
        except ValueError:
            return apology("shares should be a positive integer")
        if shares_int <= 0:
            return apology("shares should be a positive integer")
        elif shares_int > [stock["total_shares"] for stock in stocks if stock["symbol"] == symbol][0]:
            return apology("you don't own enough shares of this stock")
        else:
            shares = shares_int

        # Get the stock's name and price
        price = lookup(symbol)["price"]
        name = lookup(symbol)["name"]

        # Find the total amount
        total = price * shares

        # Insert the data
        db.execute("INSERT INTO transactions (user_id, name, symbol, price, shares, action, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                   session["user_id"], name, symbol, price, shares, "sell")

        # Update user's cash
        db.execute("UPDATE users SET cash = (cash + ?) WHERE id = ?", total, session["user_id"])

        flash(f"Sold {shares} share(s) of {name} for {usd(float(total))}")

        return redirect("/")

    else:
        return render_template("sell.html", stocks=stocks)
