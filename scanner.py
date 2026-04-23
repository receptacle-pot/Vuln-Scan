import html
import ipaddress
import json
import queue
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from flask import Response, stream_with_context

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
}

VULN_KB = {
    "FTP": ("High", "Unencrypted file transfer can expose credentials.", "Disable FTP or migrate to SFTP/FTPS."),
    "Telnet": ("Critical", "Telnet sends plaintext credentials and sessions.", "Disable Telnet; use SSH with key-based auth."),
    "SMB": ("High", "SMB can expose file shares and legacy vulnerabilities.", "Restrict SMB, patch OS, disable SMBv1."),
    "RDP": ("High", "Remote desktop exposed to network brute force and exploits.", "Use VPN, enable MFA, restrict source IPs."),
    "Redis": ("Critical", "Unauthenticated Redis may allow remote code execution.", "Bind to localhost, require auth, firewall port 6379."),
    "MySQL": ("Medium", "Database service exposure may leak data if misconfigured.", "Restrict network access and rotate credentials."),
    "PostgreSQL": ("Medium", "Database exposed to unnecessary network segments.", "Limit listen addresses and enforce strong auth."),
    "HTTP": ("Medium", "Web service may be vulnerable without hardening.", "Patch web stack, enforce secure headers, run WAF."),
    "HTTPS": ("Low", "TLS service still needs cert and config hygiene.", "Use modern TLS versions/ciphers and renew certificates."),
    "SSH": ("Low", "SSH can be brute-forced if internet-exposed.", "Disable password auth; enable keys + fail2ban."),
}

SEVERITY_SCORE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


@dataclass
class ScanState:
    target: str
    top_ports: int
    status: str = "queued"
    progress: int = 0
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    messages: "queue.Queue[str]" = field(default_factory=queue.Queue)
    result: Dict | None = None


class ScanManager:
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.scans: Dict[str, ScanState] = {}

    def create_scan(self, target: str, top_ports: int = 1024) -> str:
        target_ip = self._validate_and_resolve_target(target)
        top_ports = max(1, min(top_ports, 3000))
        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(target=target_ip, top_ports=top_ports)
        self.scans[scan_id] = state
        thread = threading.Thread(target=self._run_scan, args=(scan_id,), daemon=True)
        thread.start()
        return scan_id

    def get_result(self, scan_id: str):
        state = self.scans.get(scan_id)
        if not state:
            return None
        return {
            "scan_id": scan_id,
            "target": state.target,
            "status": state.status,
            "progress": state.progress,
            "result": state.result,
        }

    def stream(self, scan_id: str):
        state = self.scans.get(scan_id)
        if not state:
            return Response("event: error\ndata: Scan not found\n\n", mimetype="text/event-stream")

        @stream_with_context
        def event_stream():
            while True:
                try:
                    msg = state.messages.get(timeout=1)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    pass

                if state.status in {"completed", "failed"}:
                    yield f"data: {json.dumps({'type': 'complete', 'status': state.status})}\n\n"
                    break

        return Response(event_stream(), mimetype="text/event-stream")

    def _run_scan(self, scan_id: str):
        state = self.scans[scan_id]
        try:
            state.status = "running"
            self._emit(state, "info", f"Starting scan on {state.target}")
            open_ports = self._scan_ports(state)
            hosts = self._network_discovery(state.target)

            vulnerabilities = self._assess_vulnerabilities(open_ports)
            risk_summary = self._risk_summary(vulnerabilities)

            state.result = {
                "open_ports": open_ports,
                "hosts_discovered": hosts,
                "vulnerabilities": vulnerabilities,
                "risk_summary": risk_summary,
                "solutions": self._solution_list(vulnerabilities),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            self._generate_html_report(scan_id, state)
            state.progress = 100
            state.status = "completed"
            state.completed_at = time.time()
            self._emit(state, "success", "Scan complete. Report generated.")
        except Exception as exc:
            state.status = "failed"
            self._emit(state, "error", f"Scan failed: {exc}")

    def _scan_ports(self, state: ScanState) -> List[Dict]:
        ports = list(range(1, state.top_ports + 1))
        open_ports = []

        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(self._check_port, state.target, port): port for port in ports}
            total = len(futures)
            for idx, fut in enumerate(as_completed(futures), start=1):
                record = fut.result()
                if record:
                    open_ports.append(record)
                    self._emit(state, "port", f"Port {record['port']} open ({record['service']})")

                if idx % 50 == 0 or idx == total:
                    pct = int((idx / total) * 70)
                    state.progress = max(state.progress, pct)

        state.progress = max(state.progress, 75)
        self._emit(state, "info", f"Port scan complete. {len(open_ports)} open ports found.")
        return sorted(open_ports, key=lambda x: x["port"])

    def _network_discovery(self, target_ip: str) -> List[str]:
        net = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        neighbors = []
        for host in list(net.hosts())[:25]:
            ip = str(host)
            if self._is_host_reachable(ip):
                neighbors.append(ip)
        return neighbors

    @staticmethod
    def _check_port(target: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            if sock.connect_ex((target, port)) == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                return {"port": port, "service": service, "state": "open"}
        finally:
            sock.close()
        return None

    @staticmethod
    def _is_host_reachable(ip: str) -> bool:
        for port in (80, 443, 22):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    return True
            finally:
                sock.close()
        return False

    def _assess_vulnerabilities(self, open_ports: List[Dict]) -> List[Dict]:
        findings = []
        for item in open_ports:
            service = item["service"]
            severity, description, recommendation = VULN_KB.get(
                service,
                ("Info", "No mapped issue in local knowledge base.", "Perform manual verification and service fingerprinting."),
            )
            findings.append(
                {
                    "port": item["port"],
                    "service": service,
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation,
                    "cvss_estimate": self._cvss_estimate(severity),
                }
            )
        return findings

    @staticmethod
    def _cvss_estimate(severity: str) -> float:
        return {
            "Critical": 9.3,
            "High": 8.0,
            "Medium": 5.6,
            "Low": 3.2,
            "Info": 0.0,
        }[severity]

    def _risk_summary(self, vulnerabilities: List[Dict]) -> Dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for item in vulnerabilities:
            counts[item["severity"]] += 1

        weighted = sum(SEVERITY_SCORE[k] * v for k, v in counts.items())
        if counts["Critical"] > 0:
            overall = "Critical"
        elif weighted >= 8:
            overall = "High"
        elif weighted >= 4:
            overall = "Medium"
        elif weighted > 0:
            overall = "Low"
        else:
            overall = "Info"

        return {"overall": overall, "counts": counts, "weighted_score": weighted}

    @staticmethod
    def _solution_list(vulnerabilities: List[Dict]) -> List[str]:
        uniq = []
        seen = set()
        for v in vulnerabilities:
            rec = v["recommendation"]
            if rec not in seen:
                seen.add(rec)
                uniq.append(rec)
        return uniq

    def _emit(self, state: ScanState, event_type: str, message: str):
        payload = json.dumps(
            {
                "type": event_type,
                "message": message,
                "progress": state.progress,
                "timestamp": time.strftime("%H:%M:%S"),
            }
        )
        state.messages.put(payload)

    def _validate_and_resolve_target(self, target: str) -> str:
        if target in {"localhost", "127.0.0.1"}:
            return "127.0.0.1"

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            raise ValueError("Could not resolve target host.") from exc

        ip_obj = ipaddress.ip_address(ip)
        if not (ip_obj.is_private or ip_obj.is_loopback):
            raise ValueError("For safety, this lab scanner only allows localhost/private IP targets.")
        return ip

    def _generate_html_report(self, scan_id: str, state: ScanState):
        result = state.result or {}
        path = self.reports_dir / f"scan_{scan_id}.html"
        vuln_rows = "\n".join(
            f"<tr><td>{v['port']}</td><td>{html.escape(v['service'])}</td><td>{v['severity']}</td><td>{html.escape(v['description'])}</td><td>{html.escape(v['recommendation'])}</td></tr>"
            for v in result.get("vulnerabilities", [])
        )
        if not vuln_rows:
            vuln_rows = "<tr><td colspan='5'>No vulnerabilities mapped.</td></tr>"

        counts = result.get("risk_summary", {}).get("counts", {})
        html_body = f"""
<!doctype html>
<html>
<head>
<meta charset='utf-8'>
<title>Scan Report {scan_id}</title>
<style>
body{{font-family:Arial,sans-serif;margin:32px;background:#f4f7fb;color:#1d2a44}}
.card{{background:#fff;border-radius:10px;padding:20px;margin-bottom:20px;box-shadow:0 8px 24px rgba(0,0,0,.08)}}
table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #d9e1f2;padding:8px;text-align:left}}
th{{background:#ecf2ff}}
</style>
</head>
<body>
<h1>Vulnerability Assessment Report</h1>
<div class='card'>
<p><b>Target:</b> {html.escape(state.target)}</p>
<p><b>Generated at:</b> {result.get('generated_at','')}</p>
<p><b>Overall Risk:</b> {result.get('risk_summary',{}).get('overall','Info')}</p>
<p><b>Risk Counts:</b> Critical={counts.get('Critical',0)}, High={counts.get('High',0)}, Medium={counts.get('Medium',0)}, Low={counts.get('Low',0)}</p>
</div>
<div class='card'>
<h2>Open Ports</h2>
<ul>
{''.join(f"<li>{p['port']} - {html.escape(p['service'])}</li>" for p in result.get('open_ports', [])) or '<li>No open ports found in selected range.</li>'}
</ul>
</div>
<div class='card'>
<h2>Vulnerabilities & Recommendations</h2>
<table>
<tr><th>Port</th><th>Service</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
{vuln_rows}
</table>
</div>
</body>
</html>
"""
        path.write_text(html_body, encoding="utf-8")
