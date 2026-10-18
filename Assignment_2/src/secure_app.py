# secure_app.py
# Secure version of the admin console.
# Defends against OS command injection (WEB404 Unit 2.5, 2.7).

from flask import Flask, request, render_template_string
import subprocess
import re
import ipaddress

app = Flask(__name__)

PAGE = """
<!doctype html>
<title>Server Admin Console (SECURE)</title>
<h2>Server Admin Console (Secure Version)</h2>
<p>Allowed actions only. Enter a host to ping:</p>
<form method="POST">
    <input name="host" size="40" placeholder="e.g. 127.0.0.1" value="{{ host }}">
    <button type="submit">Ping</button>
</form>
{% if output %}
<h3>Result:</h3>
<pre>{{ output }}</pre>
{% endif %}
{% if error %}
<h3 style="color:red">Rejected:</h3>
<pre style="color:red">{{ error }}</pre>
{% endif %}
"""

# ---- DEFENCE 1: Input validation (allowlist of characters) ----
# A valid host is only letters, digits, dots and hyphens.
# Anything else (; | & $ ` spaces ...) is rejected before we do anything.
HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")

def is_valid_host(host):
    if not host or len(host) > 253:          # sensible length limit
        return False
    if not HOST_PATTERN.match(host):          # only safe characters
        return False
    return True

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    error = ""
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "").strip()

        if not is_valid_host(host):
            error = "Invalid host. Only letters, digits, dots and hyphens are allowed."
        else:
            try:
                # ---- DEFENCE 2: No shell ----
                # The command is a LIST, not a string, and shell=False (the default).
                # Each item is passed directly to the program as a separate argument,
                # so shell characters have no special meaning. This is the main fix.
                #
                # ---- DEFENCE 3: Fixed command (allowlist of action) ----
                # The user can ONLY ping. They cannot choose the command itself.
                #
                # ---- DEFENCE 4: Timeout ----
                # The command cannot run forever.
                result = subprocess.run(
                    ["ping", "-c", "2", host],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    output = result.stdout
                else:
                    # ---- DEFENCE 5: Safe error message ----
                    # Don't leak raw system errors to the user.
                    output = "Host could not be reached."
            except subprocess.TimeoutExpired:
                error = "The request timed out."
            except Exception:
                error = "An unexpected error occurred."

    return render_template_string(PAGE, output=output, error=error, host=host)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)  # debug off: no info leak