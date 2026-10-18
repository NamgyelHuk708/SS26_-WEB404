# vulnerable_upload.py
# WARNING: Intentionally insecure. Run on localhost only.
# Demonstrates insecure file upload (WEB404 Unit 2.3).

from flask import Flask, request, render_template_string, send_from_directory
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "..", "uploads_vulnerable"))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

PAGE = """
<!doctype html>
<title>Profile Picture Upload (VULNERABLE)</title>
<h2>Upload your profile picture</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
{% if message %}<p><b>{{ message }}</b></p>{% endif %}
{% if uploaded %}
<p>File saved! View it here:
   <a href="/uploads/{{ uploaded }}">/uploads/{{ uploaded }}</a></p>
{% endif %}
"""

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    uploaded = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # ---- THE VULNERABILITY ----
            # The user's filename is trusted completely: no checks, no renaming.
            filepath = os.path.join(UPLOAD_FOLDER, f.filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            f.save(filepath)
            uploaded = f.filename
            message = "Upload successful."
    return render_template_string(PAGE, message=message, uploaded=uploaded)

@app.route("/uploads/<path:name>")
def serve_upload(name):
    return send_from_directory(UPLOAD_FOLDER, name)

if __name__ == "__main__":
    print("Upload folder is:", UPLOAD_FOLDER)
    app.run(host="127.0.0.1", port=5001, debug=True)