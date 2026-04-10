import os
import random
import time
from datetime import datetime

from flask import Flask, jsonify, request, send_file
import mysql.connector
import fetch_threats

app = Flask(__name__)

# ── CONFIG ───────────────────────────────────────────────────
DB_HOST     = "localhost"
DB_PORT     = 3306
DB_USER     = "root"
DB_PASSWORD = "root"
DB_NAME     = "blue_db"

def get_conn():
    return mysql.connector.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASSWORD, database=DB_NAME
    )

def run_q(sql, params=None):
    try:
        c = get_conn()
        cur = c.cursor(dictionary=True)
        cur.execute(sql, params or ())
        rows = cur.fetchall()
        cur.close()
        c.close()
        return rows
    except Exception as e:
        print(f"DB Error: {e}")
        return []

def scalar(sql, params=None):
    rows = run_q(sql, params)
    if not rows:
        return 0
    return list(rows[0].values())[0] or 0

# ── ROUTES ───────────────────────────────────────────────────

@app.route("/")
def index():
    # Serve index.html
    return send_file("index.html")

@app.route("/api/dashboard")
def dashboard():
    try:
        # Check DB connection explicitly
        c = get_conn()
        c.close()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

    ti = int(scalar("SELECT COUNT(*) FROM INDICATORS"))
    ts = int(scalar("SELECT COUNT(*) FROM SIGHTINGS"))
    ta = int(scalar("SELECT COUNT(*) FROM ANOMALIES"))
    tr = int(scalar("SELECT COUNT(*) FROM SOURCES"))

    recent = run_q("""
        SELECT i.indicator_id AS id, i.type, i.value,
               i.confidence_score AS conf,
               COALESCE(ta.name,'—') AS actor,
               DATE_FORMAT(i.first_seen,'%Y-%m-%d %H:%i') AS fs,
               DATE_FORMAT(i.last_seen, '%Y-%m-%d %H:%i') AS ls
        FROM INDICATORS i
        LEFT JOIN THREAT_ACTORS ta ON i.actor_id=ta.actor_id
        ORDER BY i.last_seen DESC LIMIT 10
    """)

    activity = run_q("""
        SELECT SUBSTRING(i.value,1,50) AS msg,
               DATE_FORMAT(s.timestamp,'%H:%i') AS t,
               s.count AS cnt
        FROM SIGHTINGS s
        JOIN INDICATORS i ON s.indicator_id=i.indicator_id
        ORDER BY s.timestamp DESC LIMIT 7
    """)

    chart = run_q("""
        SELECT DATE_FORMAT(timestamp, '%W') as day_name, DATE(timestamp) AS day, SUM(count) AS total
        FROM SIGHTINGS WHERE timestamp >= NOW() - INTERVAL 7 DAY
        GROUP BY day_name, day ORDER BY day ASC
    """)
    
    # Fill in week if missing
    import datetime as dt
    days_data = []
    for i in range(6, -1, -1):
        target_date = dt.date.today() - dt.timedelta(days=i)
        found = next((c for c in chart if str(c['day']) == str(target_date)), None)
        total = int(found['total']) if found else 0
        days_data.append({
            "day": target_date.strftime("%a").upper(),
            "total": total
        })

    return jsonify({
        "metrics": {"indicators": ti, "sightings": ts, "anomalies": ta, "sources": tr},
        "recent": recent,
        "activity": activity,
        "chart": days_data
    })

@app.route("/api/alerts")
def alerts():
    anomalies = run_q("""
        SELECT a.anomaly_id, i.value AS indicator, i.type, a.severity, 
               CAST(a.z_score AS FLOAT) AS z_score, a.detection_reason, DATE_FORMAT(a.detected_at, '%Y-%m-%d %H:%i') AS detected_at
        FROM ANOMALIES a
        JOIN INDICATORS i ON a.indicator_id = i.indicator_id
        ORDER BY a.detected_at DESC
    """)
    return jsonify({"anomalies": anomalies})

@app.route("/api/search")
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"success": False, "error": "No query provided"})
    
    # Simple search prioritizing indicators
    res = run_q("""
        SELECT i.indicator_id AS id, i.type, i.value, i.confidence_score, 
               DATE_FORMAT(i.first_seen, '%Y-%m-%d') as fs,
               ta.name AS actor
        FROM INDICATORS i
        LEFT JOIN THREAT_ACTORS ta ON i.actor_id = ta.actor_id
        WHERE i.value LIKE %s OR ta.name LIKE %s
        LIMIT 1
    """, (f"%{q}%", f"%{q}%"))

    if not res:
        return jsonify({"success": False})

    return jsonify({"success": True, "result": res[0]})

@app.route("/api/fetch", methods=['POST'])
def run_fetch():
    try:
        res = fetch_threats.fetch_latest_data()
        return jsonify(res)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == "__main__":
    app.run(port=5000, debug=False)
