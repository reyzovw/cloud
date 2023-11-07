import sqlite3
from flask import Flask, render_template, request, make_response
from urllib.parse import quote
from random import randint
import hashlib

app = Flask(__name__)


conn = sqlite3.connect('files.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT, path BLOB, filename)')
conn.commit()

def sha256_hash(data):
    sha_signature = hashlib.sha256(data).hexdigest()
    return sha_signature

@app.route('/', methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files['file']
        if file:
            filename = file.filename
            print(filename)
            file_content = file.read()
            file_hash = sha256_hash(file_content)
            uniq_hash = f"{file_hash}{randint(512, 1024)}"
            print(uniq_hash)
            cursor.execute('INSERT OR IGNORE INTO files (hash, path, filename) VALUES (?, ?, ?)', (uniq_hash, file_content, filename))
            conn.commit()
            return render_template("success.html", link=f"d/{uniq_hash}")
        return render_template("fail.html")
    return render_template('index.html')

@app.route("/d/<string:file_hash>", methods=["GET", 'POST'])
def get_file(file_hash):
    if request.method == "POST":
        cursor.execute('SELECT filename, path FROM files WHERE hash = ?', (file_hash, ))
        data = cursor.fetchone()
        if data:
            filename, file_content = data
            quoted_filename = quote(filename)
            response = make_response(file_content)
            response.headers['Content-Type'] = 'application/octet-stream'
            response.headers['Content-Disposition'] = f'attachment; filename="{quoted_filename}"'
            
            return response
        else:
            return render_template("404.html")
        
    return render_template('download.html')

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
