# vulnerable_app.py
# WARNING: This app is intentionally insecure. Run on localhost only.
# Purpose: demonstrate OS command injection (WEB404 Unit 2.5).

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

# The web page: a simple form with one text box.
PAGE = """
<!doctype html>
<title>Server Admin Console (VULNERABLE)</title>
<h2>Server Admin Console</h2>
<p>Enter a host to ping:</p>
<form method="POST">
    <input name="host" size="40" placeholder="e.g. 127.0.0.1" value="{{ host }}">
    <button type="submit">Ping</button>
</form>
{% if output %}
<h3>Result:</h3>
<pre>{{ output }}</pre>
{% endif %}
"""

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # ---- THE VULNERABILITY ----
        # The user's input is glued directly into a shell command.
        # shell=True means the whole string is handed to the system shell,
        # so shell characters like ; && | are interpreted as commands.
        command = "ping -c 2 " + host
        output = subprocess.run(
            command, shell=True, capture_output=True, text=True
        ).stdout
        # Also show errors so the demo is clear:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
    return render_template_string(PAGE, output=output, host=host)

if __name__ == "__main__":
    # 127.0.0.1 means this is reachable ONLY from your own machine.
    app.run(host="127.0.0.1", port=5000, debug=True)