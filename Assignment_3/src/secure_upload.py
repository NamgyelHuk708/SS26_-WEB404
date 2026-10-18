# secure_upload.py
# Secure file upload (WEB404 Unit 2.3).
# Defends against: malicious file type, double extension, path traversal, oversized files.

from flask import Flask, request, render_template_string, send_from_directory, abort
import os
import uuid
import imghdr   # checks the REAL image type from the file's bytes

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "..", "uploads_secure"))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---- DEFENCE 1: Allowlist of real image types ----
ALLOWED_TYPES = {"jpeg", "png", "gif"}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}

# ---- DEFENCE 5: Maximum file size (5 MB) ----
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

PAGE = """
<!doctype html>
<title>Profile Picture Upload (SECURE)</title>
<h2>Upload your profile picture (Secure)</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
{% if message %}<p style="color:green"><b>{{ message }}</b></p>{% endif %}
{% if error %}<p style="color:red"><b>Rejected: {{ error }}</b></p>{% endif %}
{% if uploaded %}
<p>File saved safely as:
   <a href="/uploads/{{ uploaded }}">/uploads/{{ uploaded }}</a></p>
{% endif %}
"""

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""; error = ""; uploaded = ""
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            error = "No file selected."
        else:
            # ---- DEFENCE 2: Check the extension (allowlist) ----
            ext = os.path.splitext(f.filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                error = "Only .jpg, .png and .gif images are allowed."
            else:
                # ---- DEFENCE 3: Verify the REAL content, not the name ----
                # imghdr reads the file's first bytes (magic numbers) to see
                # what it ACTUALLY is. A .html renamed to .png fails here.
                header = f.stream.read(512)
                f.stream.seek(0)   # rewind so we can still save it
                real_type = imghdr.what(None, h=header)
                if real_type not in ALLOWED_TYPES:
                    error = "File content is not a valid image."
                else:
                    # ---- DEFENCE 4: We choose the name (random) and extension ----
                    # The user's filename (and any ../ in it) is thrown away.
                    safe_name = f"{uuid.uuid4().hex}.{real_type}"
                    filepath = os.path.join(UPLOAD_FOLDER, safe_name)
                    f.save(filepath)
                    uploaded = safe_name
                    message = "Upload successful and verified as a real image."
    return render_template_string(PAGE, message=message, error=error, uploaded=uploaded)

@app.route("/uploads/<name>")
def serve_upload(name):
    # <name> (no <path:>) means slashes are not allowed, blocking traversal here too.
    # as_attachment=True forces download instead of rendering in the browser.
    return send_from_directory(UPLOAD_FOLDER, name, as_attachment=True)

if __name__ == "__main__":
    print("Secure upload folder:", UPLOAD_FOLDER)
    app.run(host="127.0.0.1", port=5001, debug=False)