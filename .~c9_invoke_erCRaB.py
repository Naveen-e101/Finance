import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    data = db.execute("SELECT symbol, SUM(shares) FROM trade WHERE user_id = ? GROUP BY symbol", session["user_id"])
    price_data = list()
    name_data = list()
    total = 0
    for i in data:
        look = lookup(i["symbol"])
        i["live_price"] = usd(look["price"])
        i["name"] = look['name']
        i['shares'] = i["SUM(shares)"]
        i["total"] = usd((i["SUM(shares)"])*(look["price"]))
        total += (i["SUM(shares)"])*(look["price"])
    res = [i for i in data if not (i['SUM(shares)'] == 0)]
    user_req = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = usd(user_req[0]["cash"])
    total += user_req[0]["cash"]
    total = usd(total)
    return render_template("index.html", data=res, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("please enter symbol", 400)
        if not request.form.get("shares"):
            return apology("please enter amount", 400)

        try:
            x = int(request.form.get("shares"))
        except ValueError:
            return apology("Enter Valid Shares", 400)

        if int(request.form.get("shares")) < 1:
            return apology("Enter Valid Shares", 400)

        user_req = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = user_req[0]["cash"]
        data = lookup(request.form.get("symbol"))
        shares = int(request.form.get("shares"))
        if data == None:
            return apology("the entity doesn't exist", 400)
        print(data["symbol"], shares, data["price"], session["user_id"])
        if cash < (shares*data["price"]):
            return apology("insufficient cash", 400)
        else:
            cash = cash - (shares*data["price"])
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
            db.execute("INSERT INTO trade (symbol, shares, price, user_id, date) VALUES (?, ?, ?, ?, DATETIME())",
                       data["symbol"], shares, data["price"], session["user_id"])
            flash("Bought!")
            return redirect("/")

    else:
        return render_template("buy.html", value="buy")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_req = db.execute("SELECT * FROM trade WHERE user_id = ?", session["user_id"])
    for i in user_req:
        i["price"] = usd(i["price"])
    return render_template("history.html", data=user_req)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Please enter Symbol", 400)
        data = lookup(request.form.get("symbol"))
        if data == None:
            return apology("The entity Doesn't exist", 400)

        data["price"] = usd(data["price"])

        return render_template("quoted.html", data=data)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("Must provide username", 400)

        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("please ensure that you enterd same password", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) == 1:
            return apology("username already taken", 400)

        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, password)
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]
        flash("Registered!")
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("please enter symbol", 403)
        if not request.form.get("shares"):
            return apology("please enter amount", 403)

        user_req = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        user_shares = db.execute("SELECT SUM(shares) FROM trade WHERE user_id = ? AND symbol= ? group by symbol",
                                 session["user_id"], request.form.get("symbol"))
        cash = user_req[0]["cash"]
        share_count = user_shares[0]["SUM(shares)"]
        print(share_count)
        data = lookup(request.form.get("symbol"))
        shares = (-1)*int(request.form.get("shares"))
        if data == None:
            return apology("the entity doesn't exist", 403)
        print(data["symbol"], shares, data["price"], session["user_id"])

        if int(request.form.get("shares")) > share_count:
            return apology("Insufficent shares to sell")
        else:
            cash = cash - (shares*data["price"])
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
            db.execute("INSERT INTO trade (symbol, shares, price, user_id, date) VALUES (?, ?, ?, ?, DATETIME())",
                       data["symbol"], shares, data["price"], session["user_id"])
            flash("Sold!")
            return redirect("/")

    else:
        data = db.execute("SELECT symbol,SUM(shares) FROM trade WHERE user_id = ? GROUP BY symbol", session["user_id"])
        res = [i for i in data if not (i['SUM(shares)'] == 0)]
        return render_template("sell.html", data=res)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
