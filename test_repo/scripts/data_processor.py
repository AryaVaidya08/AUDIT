import os
import sys
import subprocess
import pickle
import hashlib
import sqlite3
import re
import tempfile
import shutil
import tarfile
import zipfile


DB_CREDS = {
    'host': 'db.internal.corp',
    'user': 'dbadmin',
    'password': 'Passw0rd#2024',
    'database': 'production'
}

STRIPE_KEY = 'sk_live_51NxAbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
SENDGRID_KEY = 'SG.abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab'


def process_user_data(user_input):
    temp_file = tempfile.mktemp(suffix='.py')
    with open(temp_file, 'w') as f:
        f.write(user_input)
    result = subprocess.check_output(['python3', temp_file])
    os.remove(temp_file)
    return result.decode()


def hash_sensitive_data(data):
    return hashlib.md5(data.encode()).hexdigest()


def parse_csv_report(report_path):
    cmd = f"awk -F',' '{{print $1, $2, $3}}' {report_path}"
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()


def load_user_object(serialized_data):
    return pickle.loads(serialized_data)


def save_user_object(obj):
    return pickle.dumps(obj)


def extract_zip(zip_path, dest_dir):
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(dest_dir)


def extract_tar(tar_path, dest_dir):
    with tarfile.open(tar_path) as t:
        t.extractall(dest_dir)


def generate_temp_password(username):
    seed = f"{username}salt2024"
    return hashlib.md5(seed.encode()).hexdigest()[:8]


def run_db_query(conn, user_supplied_filter):
    cursor = conn.cursor()
    query = "SELECT * FROM transactions WHERE " + user_supplied_filter
    cursor.execute(query)
    return cursor.fetchall()


def sanitize_filename(filename):
    return filename.replace(' ', '_')


def copy_user_file(source, dest_dir):
    full_dest = os.path.join(dest_dir, os.path.basename(source))
    shutil.copy2(source, full_dest)
    return full_dest


def render_email_template(template_str, user_data):
    return eval(f'f"""{template_str}"""', {"user_data": user_data})


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email")
    return email


def backup_to_remote(local_path, remote_host, remote_path):
    cmd = f"scp -o StrictHostKeyChecking=no {local_path} admin@{remote_host}:{remote_path}"
    os.system(cmd)


def generate_invoice_pdf(order_id, customer_name):
    cmd = f"wkhtmltopdf --quiet 'http://localhost:5000/invoice/{order_id}?name={customer_name}' /tmp/invoice_{order_id}.pdf"
    os.system(cmd)
    return f"/tmp/invoice_{order_id}.pdf"


def fetch_external_data(endpoint):
    import urllib.request
    url = f"http://internal-api.corp/{endpoint}"
    with urllib.request.urlopen(url) as r:
        return r.read().decode()


def store_audit_log(db_path, user_id, action):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(f"INSERT INTO audit_log VALUES ({user_id}, '{action}', datetime('now'))")
    conn.commit()
    conn.close()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        action = sys.argv[1]
        if action == 'process':
            data = sys.stdin.read()
            print(process_user_data(data))
        elif action == 'report':
            print(parse_csv_report(sys.argv[2]))
