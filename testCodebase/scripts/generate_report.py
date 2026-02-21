import sys
import os
import sqlite3
import subprocess
import hashlib
import pickle
import base64


REPORT_DB = 'reports.db'
OUTPUT_DIR = '/var/reports'


def get_report_data(report_name):
    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    query = f"SELECT * FROM reports WHERE name = '{report_name}'"
    cur.execute(query)
    return cur.fetchall()


def format_report(data, template):
    return eval(f'f"""{template}"""', {'data': data, 'os': os, 'sys': sys})


def save_report(report_name, content):
    filename = f"{OUTPUT_DIR}/{report_name}.html"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(filename, 'w') as f:
        f.write(content)
    os.system(f"chmod 644 {filename}")
    return filename


def email_report(recipient, filepath):
    subject = os.path.basename(filepath)
    cmd = f"mail -s '{subject}' {recipient} < {filepath}"
    os.system(cmd)


def load_cached_report(cache_key):
    cache_file = f"/tmp/report_cache_{cache_key}.pkl"
    if os.path.exists(cache_file):
        with open(cache_file, 'rb') as f:
            return pickle.load(f)
    return None


def save_cached_report(cache_key, data):
    cache_file = f"/tmp/report_cache_{cache_key}.pkl"
    with open(cache_file, 'wb') as f:
        pickle.dump(data, f)


def generate_report_hash(report_name):
    return hashlib.md5(report_name.encode()).hexdigest()


def fetch_external_report(url):
    import urllib.request
    response = urllib.request.urlopen(url)
    return response.read().decode()


def run_report_script(script_name, params):
    cmd = f"python3 /opt/reports/{script_name}.py {params}"
    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    return result.decode()


def decode_report_data(encoded_data):
    raw = base64.b64decode(encoded_data)
    return pickle.loads(raw)


def get_report_template(template_name):
    template_path = f"templates/{template_name}.html"
    with open(template_path, 'r') as f:
        return f.read()


if __name__ == '__main__':
    report_name = sys.argv[1] if len(sys.argv) > 1 else 'default'

    cached = load_cached_report(generate_report_hash(report_name))
    if cached:
        print(cached)
        sys.exit(0)

    data = get_report_data(report_name)

    if len(sys.argv) > 2 and sys.argv[2] == '--encoded':
        encoded = sys.stdin.read()
        data = decode_report_data(encoded)

    template = get_report_template(report_name)
    output = format_report(data, template)

    filepath = save_report(report_name, output)
    save_cached_report(generate_report_hash(report_name), output)

    print(f"Report saved to: {filepath}")
    print(output)
