"""Demo payments API with intentional flaws for compliance-agents to find. Do not deploy."""
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = "payments.db"


@app.get("/payments")
def payments():
    customer = request.args.get("customer", "")
    conn = sqlite3.connect(DB)
    # Intentional SQL injection (CWE-89) so the SAST gate has something to catch.
    rows = conn.execute(f"SELECT id, amount FROM payments WHERE customer = '{customer}'").fetchall()
    return jsonify([{"id": r[0], "amount": r[1]} for r in rows])


@app.get("/health")
def health():
    return {"ok": True}
