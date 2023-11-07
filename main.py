import sqlite3
from flask import Flask, render_template, request, make_response
from urllib.parse import quote
from random import randint
import hashlib
import requests

app = Flask(__name__)


conn = sqlite3.connect('files.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT, path BLOB, filename)')
conn.commit()

def sha256_hash(data):
    sha_signature = hashlib.sha256(data).hexdigest()
    return sha_signature

def load_file_from_database(hash):
    conn = sqlite3.connect('files.db')  # Замените 'your_database.db' на имя вашей базы данных
    cursor = conn.cursor()
    cursor.execute("SELECT path FROM files WHERE hash = ?", (hash, ))
    file_data = cursor.fetchone()[0]
    conn.close()
    return file_data

# Функция для вычисления хэш-суммы файла
def calculate_hash(file_data):
    sha256 = hashlib.sha256()
    sha256.update(file_data)
    return sha256.hexdigest()

# Функция для отправки файла на анализ в VirusTotal
def scan_file_with_virustotal(api_key, file_data):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': ('filename', file_data)}
    response = requests.post(url, files=files, params=params)
    return response.json()



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

def check_vt(file_hash, file_data):
    api_key = '10f696e9f25650fd53777f2b4f9dfd686067e533b4e1dff720ecd6534f40aef5'

    url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={file_hash}'
    response = requests.get(url)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 0:
            scan_response = scan_file_with_virustotal(api_key, file_data)
            return scan_response["positives"]
        else:
            return json_response["positives"]
    else:
        return 0

@app.route("/d/<string:file_hash>", methods=["GET", 'POST'])
def get_file(file_hash):
    fd = load_file_from_database(file_hash)
    vt_result = check_vt(calculate_hash(fd), fd)
    
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
    
    return render_template('download.html', file_hash=file_hash, vt=vt_result)

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
