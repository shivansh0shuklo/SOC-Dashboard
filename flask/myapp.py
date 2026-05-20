from flask import  Flask,render_template
import psycopg as magic
db_info = "dbname=soc_dashboard user=shivansh password=aftermeth host=localhost"
def database_establiseh_return_list():
    with magic.connect(db_info) as connect:
        with connect.cursor() as curr:
            curr.execute("SELECT event_type, sevirity, details, created_at, file_path, hash_value FROM alerts")
            rows  = curr.fetchall()
    return rows

dictionary  = {"name":"secret-code","age":34}
app = Flask(__name__)
@app.route("/")
def index():
    log_data  =database_establiseh_return_list()
    return render_template('index.html',alerts =log_data)

if(__name__ == '__main__'):
    app.run(debug=True,port=5000)