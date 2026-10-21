# secure_sql.py
# Secure version using parameterised queries (WEB404 Unit 2.1.3, 2.7.2).

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "secure.db")

def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)")
    cur.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "admin",  "SuperSecret123", "admin"),
        (2, "namgyel", "pass4567",       "user"),
        (3, "guest",  "guest",           "user"),
    ])
    cur.execute("CREATE TABLE products (id INTEGER, name TEXT, price TEXT)")
    cur.executemany("INSERT INTO products VALUES (?,?,?)", [
        (1, "Laptop",   "800"),
        (2, "Keyboard", "25"),
        (3, "Mouse",    "15"),
    ])
    con.commit()
    con.close()

LOGIN_PAGE = """
<!doctype html><title>Login (SECURE)</title>
<h2>Login (Secure)</h2>
<form method="POST">
  Username: <input name="username"><br><br>
  Password: <input name="password"><br><br>
  <button type="submit">Log in</button>
</form>
{% if result %}<p><b>{{ result }}</b></p>{% endif %}
<hr><p><a href="/search">Go to product search</a></p>
"""

SEARCH_PAGE = """
<!doctype html><title>Search (SECURE)</title>
<h2>Product Search (Secure)</h2>
<form method="GET">
  Search: <input name="q" value="{{ q }}">
  <button type="submit">Search</button>
</form>
{% if error %}<p style="color:red"><b>Something went wrong with your search.</b></p>{% endif %}
{% if rows is not none %}
  <h3>Results:</h3>
  <table border="1" cellpadding="5">
    {% for row in rows %}<tr>{% for col in row %}<td>{{ col }}</td>{% endfor %}</tr>{% endfor %}
  </table>
{% endif %}
<hr><p><a href="/">Back to login</a></p>
"""

@app.route("/", methods=["GET", "POST"])
def login():
    result = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        con = sqlite3.connect(DB)
        try:
            cur = con.cursor()
            # ---- THE FIX: parameterised query ----
            # The ? placeholders keep user input as DATA, never as SQL.
            cur.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password)
            )
            row = cur.fetchone()
            if row:
                result = f"Login successful! Welcome {row[1]} (role: {row[3]})"
            else:
                result = "Login failed."
        except Exception:
            result = "An error occurred."   # generic: no DB details leaked
        con.close()
    return render_template_string(LOGIN_PAGE, result=result)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = None
    error = ""
    if q:
        con = sqlite3.connect(DB)
        try:
            cur = con.cursor()
            # ---- THE FIX: parameterised query ----
            # The search term is passed separately, wrapped with % for LIKE.
            cur.execute(
                "SELECT id, name, price FROM products WHERE name LIKE ?",
                ('%' + q + '%',)
            )
            rows = cur.fetchall()
        except Exception:
            error = "error"   # generic message only
        con.close()
    return render_template_string(SEARCH_PAGE, q=q, rows=rows, error=error)

if __name__ == "__main__":
    init_db()
    print("Secure database created.")
    app.run(host="127.0.0.1", port=5002, debug=False)