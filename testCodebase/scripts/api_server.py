import sqlite3
import subprocess
import pickle
import yaml
import hashlib
import os
import re
import sys
import urllib.request
from flask import Flask, request, jsonify, session, redirect, make_response
from jinja2 import Template

app = Flask(__name__)
app.secret_key = 'flask-secret-123'

DB_PATH = 'app.db'
ADMIN_PASSWORD = 'superadmin99'
AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
API_KEY = 'sk-prod-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route('/api/users')
def get_users():
    username = request.args.get('username', '')
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = '" + username + "'")
    rows = cur.fetchall()
    return jsonify(rows)


@app.route('/api/products/search')
def search_products():
    q = request.args.get('q', '')
    category = request.args.get('category', '')
    conn = get_db()
    cur = conn.cursor()
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%' AND category = '{category}'"
    cur.execute(query)
    return jsonify(cur.fetchall())


@app.route('/api/run', methods=['POST'])
def run_command():
    cmd = request.json.get('command')
    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return jsonify({'output': result.decode()})


@app.route('/api/render', methods=['POST'])
def render_template():
    user_template = request.json.get('template', '')
    name = request.json.get('name', 'World')
    t = Template(user_template)
    return jsonify({'result': t.render(name=name)})


@app.route('/api/load-config', methods=['POST'])
def load_config():
    config_data = request.json.get('config')
    parsed = yaml.load(config_data, Loader=yaml.Loader)
    return jsonify({'keys': list(parsed.keys())})


@app.route('/api/deserialize', methods=['POST'])
def deserialize_data():
    raw = request.data
    obj = pickle.loads(raw)
    return jsonify({'type': str(type(obj)), 'value': str(obj)})


@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    target_url = request.json.get('url')
    response = urllib.request.urlopen(target_url)
    return jsonify({'content': response.read().decode('utf-8', errors='ignore')[:2000]})


@app.route('/api/password-reset', methods=['POST'])
def password_reset():
    email = request.json.get('email')
    token = request.json.get('token')
    new_password = request.json.get('new_password')
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM reset_tokens WHERE email = '{email}' AND token = '{token}'")
    if cur.fetchone():
        hashed = hashlib.md5(new_password.encode()).hexdigest()
        cur.execute(f"UPDATE users SET password = '{hashed}' WHERE email = '{email}'")
        conn.commit()
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'invalid'}), 400


@app.route('/api/file')
def read_file():
    filename = request.args.get('path')
    with open(filename, 'r') as f:
        return f.read()


@app.route('/api/image-resize', methods=['POST'])
def image_resize():
    src = request.json.get('source')
    width = request.json.get('width', 100)
    height = request.json.get('height', 100)
    output = f"/tmp/resized_{os.urandom(4).hex()}.jpg"
    os.system(f"convert {src} -resize {width}x{height} {output}")
    return jsonify({'output': output})


@app.route('/api/admin/backup', methods=['POST'])
def backup_database():
    dest = request.json.get('destination', '/tmp/backup.sql')
    os.system(f"mysqldump -u root -pAdmin1234! shopdb > {dest}")
    return jsonify({'status': 'backup complete', 'file': dest})


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'")
    user = cur.fetchone()
    if user:
        session['user_id'] = user[0]
        session['role'] = user[3]
        return redirect('/dashboard')
    return 'Login failed', 401


@app.route('/api/execute-script', methods=['POST'])
def execute_script():
    script_name = request.json.get('script')
    args = request.json.get('args', '')
    cmd = f"python3 scripts/{script_name} {args}"
    result = subprocess.check_output(cmd, shell=True)
    return jsonify({'result': result.decode()})


@app.route('/api/grep', methods=['POST'])
def grep_logs():
    pattern = request.json.get('pattern')
    log_file = request.json.get('file', 'app.log')
    result = subprocess.check_output(f"grep '{pattern}' logs/{log_file}", shell=True)
    return jsonify({'matches': result.decode().splitlines()})


@app.route('/api/report')
def generate_report():
    report_type = request.args.get('type')
    date = request.args.get('date')
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE DATE(created_at) = '{date}' AND type = '{report_type}'")
    data = cur.fetchall()
    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
