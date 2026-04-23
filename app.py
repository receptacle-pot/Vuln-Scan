from flask import Flask, jsonify, render_template, request, send_file, url_for
from pathlib import Path
from scanner import ScanManager

app = Flask(__name__)
app.config["REPORTS_DIR"] = Path("reports")
app.config["REPORTS_DIR"].mkdir(parents=True, exist_ok=True)

scan_manager = ScanManager(reports_dir=app.config["REPORTS_DIR"])


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def create_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    top_ports = int(data.get("top_ports", 1000))
    if not target:
        return jsonify({"error": "Target is required."}), 400

    try:
        scan_id = scan_manager.create_scan(target=target, top_ports=top_ports)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "scan_id": scan_id,
        "stream_url": url_for("scan_stream", scan_id=scan_id),
        "result_url": url_for("scan_result", scan_id=scan_id),
    })


@app.get("/api/scan/<scan_id>/stream")
def scan_stream(scan_id: str):
    return scan_manager.stream(scan_id)


@app.get("/api/scan/<scan_id>/result")
def scan_result(scan_id: str):
    result = scan_manager.get_result(scan_id)
    if result is None:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify(result)


@app.get("/reports/<scan_id>")
def report(scan_id: str):
    path = app.config["REPORTS_DIR"] / f"scan_{scan_id}.html"
    if not path.exists():
        return jsonify({"error": "Report not generated yet."}), 404
    return send_file(path)


if __name__ == "__main__":
    app.run(debug=True)