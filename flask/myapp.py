from flask import Flask, render_template
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'soc_dashboard.db')


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def database_establiseh_return_list():
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT event_type, severity, details, created_at, file_path, hash_value FROM alerts ORDER BY id DESC"
        ).fetchall()
    return [tuple(row) for row in rows]


app = Flask(__name__)


@app.route("/")
def index():
    log_data = database_establiseh_return_list()
    return render_template('index.html', alerts=log_data)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8000)
