# backend.py
# A tiny, deliberately simple backend app that sits BEHIND the WAF.
# It just echoes back what it receives, so we can see what the WAF let through.

from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "Backend app is alive. Try /search?q=test or /ping?host=127.0.0.1\n"

@app.route("/search")
def search():
    # Imagine this is a search box. It echoes the query back.
    q = request.args.get("q", "")
    return f"You searched for: {q}\n"

@app.route("/ping")
def ping():
    # Imagine this runs a ping. It just echoes the host back (no real command).
    host = request.args.get("host", "")
    return f"Pinging host: {host}\n"

if __name__ == "__main__":
    # Listen on all interfaces so the WAF container can reach it.
    app.run(host="0.0.0.0", port=8500, debug=False)