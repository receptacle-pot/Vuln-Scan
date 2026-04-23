import html
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import shutil
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
    8009: "AJP13",
    8180: "HTTP-Alt",
}

VULN_KB = {
    "FTP": ("High", "Unencrypted file transfer can expose credentials.", "Disable FTP or migrate to SFTP/FTPS."),
    "SSH": ("Low", "SSH can be brute-forced if internet-exposed.", "Disable password auth; use keys + fail2ban."),
    "Telnet": ("Critical", "Telnet sends plaintext credentials and sessions.", "Disable Telnet; replace with SSH."),
    "SMTP": ("Medium", "Mail services may allow spoofing or open relay if weakly configured.", "Restrict relay policies and patch MTA."),
    "DNS": ("Medium", "DNS can be abused for amplification or zone leakage.", "Disable open recursion and restrict zone transfers."),
    "HTTP": ("Medium", "Web service may expose vulnerable apps or default pages.", "Patch stack, harden headers, and review auth controls."),
    "RPCbind": ("High", "RPC services can expose internal service mapping.", "Restrict RPC to trusted networks and firewall aggressively."),
    "NetBIOS": ("High", "Legacy NetBIOS may leak host/share info.", "Disable where possible and restrict SMB/NetBIOS access."),
    "SMB": ("High", "SMB may expose shares and legacy protocol vulnerabilities.", "Disable SMBv1, patch regularly, restrict shares."),
    "MySQL": ("Medium", "Database service exposure increases attack surface.", "Bind to internal interfaces and enforce strong credentials."),
    "PostgreSQL": ("Medium", "Database exposed beyond required segments.", "Restrict listen addresses and enforce TLS/auth."),
    "VNC": ("High", "VNC is often weakly protected and remotely exploitable.", "Place behind VPN, strong auth, and network ACLs."),
    "AJP13": ("High", "AJP connectors may expose backend app containers.", "Disable unused AJP or enforce secrets and ACLs."),
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
        self.nmap_binary = self._resolve_nmap_binary()

    def create_scan(self, target: str, top_ports: int = 1000) -> str:
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
        state.status = "running"
        try:
            self._emit(state, "info", f"Running Nmap scan on {state.target} (top {state.top_ports} ports)")
            nmap_result = self._run_nmap_scan(state)
            state.progress = 78
            self._emit(state, "info", f"Scan found {len(nmap_result['open_ports'])} open ports.")

            self._emit(state, "info", "Running lightweight neighborhood discovery in /24 subnet...")
            hosts = self._network_discovery(state.target)
            state.progress = 90

            vulnerabilities = self._assess_vulnerabilities(nmap_result["open_ports"])
            risk_summary = self._risk_summary(vulnerabilities)

            warnings = list(nmap_result.get("warnings", []))
            if not nmap_result["open_ports"]:
                warnings.append("No open ports were found. Target may be filtered, unreachable, or outside scanner network path.")

            state.result = {
                "open_ports": nmap_result["open_ports"],
                "hosts_discovered": hosts,
                "vulnerabilities": vulnerabilities,
                "risk_summary": risk_summary,
                "solutions": self._solution_list(vulnerabilities),
                "nmap_command": nmap_result["command"],
                "nmap_raw_output": nmap_result["raw_output"],
                "scan_engine": nmap_result.get("engine", "nmap"),
                "warnings": warnings,
                "error": None,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            state.progress = 100
            state.status = "completed"
            state.completed_at = time.time()
            self._emit(state, "success", "Scan complete. Report generated.")
        except Exception as exc:
            state.status = "failed"
            state.result = {
                "open_ports": [],
                "hosts_discovered": [],
                "vulnerabilities": [],
                "risk_summary": {"overall": "Info", "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}, "weighted_score": 0},
                "solutions": [],
                "nmap_command": "",
                "nmap_raw_output": "",
                "scan_engine": "none",
                "warnings": [],
                "error": str(exc),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            self._emit(state, "error", f"Scan failed: {exc}")
        finally:
            self._generate_html_report(scan_id, state)

    def _run_nmap_scan(self, state: ScanState) -> Dict:
        command = [self.nmap_binary, "-Pn", "--top-ports", str(state.top_ports), state.target]

        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
        except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired) as exc:
            self._emit(state, "info", f"Nmap execution issue ({exc.__class__.__name__}). Falling back to internal TCP scan.")
            fallback = self._socket_fallback_scan(state.target, state.top_ports, state)
            return {
                "open_ports": fallback,
                "raw_output": "Nmap was unavailable or failed to execute, so socket-based fallback scanning was used.",
                "command": "socket_fallback_scan",
                "engine": "socket_fallback",
                "warnings": [f"Nmap execution issue: {exc.__class__.__name__}"],
            }

        raw_output = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()

        if completed.returncode != 0:
            self._emit(state, "info", "Nmap returned a non-zero status. Falling back to internal TCP scan.")
            fallback = self._socket_fallback_scan(state.target, state.top_ports, state)
            warning_text = stderr or raw_output or "Nmap returned non-zero exit status."
            return {
                "open_ports": fallback,
                "raw_output": raw_output or warning_text,
                "command": "socket_fallback_scan",
                "engine": "socket_fallback",
                "warnings": [warning_text],
            }

        open_ports = []
        for line in raw_output.splitlines():
            line = line.strip()
            match = re.match(r"^(\d+)/tcp\s+open\s+(.+)$", line)
            if not match:
                continue
            port = int(match.group(1))
            service_raw = match.group(2).split()[0]
            service = COMMON_SERVICES.get(port, service_raw.upper())
            open_ports.append({"port": port, "service": service, "state": "open"})
            self._emit(state, "port", f"{port}/tcp open ({service_raw})")
            state.progress = min(70, state.progress + 2)

        return {
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "raw_output": raw_output,
            "command": " ".join(command),
            "engine": "nmap",
            "warnings": [stderr] if stderr else [],
        }

    def _resolve_nmap_binary(self) -> str:
        env_bin = (os.getenv("NMAP_BINARY") or "").strip()
        if env_bin:
            return env_bin

        system_nmap = shutil.which("nmap")
        if system_nmap:
            return system_nmap

        common_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        ]
        for candidate in common_paths:
            if Path(candidate).exists():
                return candidate

        return "nmap"

    def _socket_fallback_scan(self, target: str, top_ports: int, state: ScanState) -> List[Dict]:
        open_ports = []
        ports = range(1, top_ports + 1)
        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(self._probe_port, target, port): port for port in ports}
            total = len(futures)
            for i, fut in enumerate(as_completed(futures), start=1):
                res = fut.result()
                if res:
                    open_ports.append(res)
                    self._emit(state, "port", f"{res['port']}/tcp open (fallback)")
                if i % 50 == 0 or i == total:
                    state.progress = max(state.progress, int((i / total) * 70))
        return sorted(open_ports, key=lambda x: x["port"])

    @staticmethod
    def _probe_port(target: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            if sock.connect_ex((target, port)) == 0:
                service = COMMON_SERVICES.get(port, "UNKNOWN")
                return {"port": port, "service": service, "state": "open"}
        finally:
            sock.close()
        return None

    def _network_discovery(self, target_ip: str) -> List[str]:
        net = ipaddress.ip_network(f"{target_ip}/24", strict=False)
        neighbors = []
        hosts = list(net.hosts())[:64]
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = {executor.submit(self._is_host_reachable, str(host)): str(host) for host in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                if fut.result():
                    neighbors.append(ip)
        return sorted(neighbors)

    @staticmethod
    def _is_host_reachable(ip: str) -> bool:
        for port in (80, 443, 22):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.08)
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
                ("Info", "No mapped issue in local knowledge base.", "Perform manual validation and version-based CVE checks."),
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
        return {"Critical": 9.3, "High": 8.0, "Medium": 5.6, "Low": 3.2, "Info": 0.0}[severity]

    def _risk_summary(self, vulnerabilities: List[Dict]) -> Dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for item in vulnerabilities:
            counts[item["severity"]] += 1

        weighted = sum(SEVERITY_SCORE[k] * v for k, v in counts.items())
        overall = "Info"
        if counts["Critical"] > 0:
            overall = "Critical"
        elif weighted >= 10:
            overall = "High"
        elif weighted >= 5:
            overall = "Medium"
        elif weighted > 0:
            overall = "Low"

        return {"overall": overall, "counts": counts, "weighted_score": weighted}

    @staticmethod
    def _solution_list(vulnerabilities: List[Dict]) -> List[str]:
        unique = []
        seen = set()
        for item in vulnerabilities:
            recommendation = item["recommendation"]
            if recommendation not in seen:
                seen.add(recommendation)
                unique.append(recommendation)
        return unique

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
            raise ValueError("Only localhost/private targets are allowed for lab safety.")
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

        open_ports = result.get("open_ports", [])
        open_list = "".join(f"<li>{p['port']}/tcp - {html.escape(p['service'])}</li>" for p in open_ports)
        if not open_list:
            open_list = "<li>No open ports found.</li>"

        risk_counts = result.get("risk_summary", {}).get("counts", {})
        warnings = result.get('warnings', [])
        warnings_html = ''.join(f"<li>{html.escape(w)}</li>" for w in warnings)
        error_text = result.get('error')
        warning_section = f"<div class='card'><h2>Warnings</h2><ul>{warnings_html}</ul></div>" if warnings_html else ""
        error_section = f"<div class='card'><h2>Error</h2><p>{html.escape(error_text)}</p></div>" if error_text else ""
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
th{{background:#ecf2ff}}pre{{white-space:pre-wrap;background:#0b1220;color:#d7e3ff;padding:12px;border-radius:8px}}
</style>
</head>
<body>
<h1>Vulnerability Assessment Report</h1>
<div class='card'>
<p><b>Target:</b> {html.escape(state.target)}</p>
<p><b>Generated At:</b> {result.get('generated_at','')}</p>
<p><b>Nmap Command:</b> {html.escape(result.get('nmap_command',''))}</p>
<p><b>Overall Risk:</b> {result.get('risk_summary',{}).get('overall','Info')}</p>
<p><b>Engine:</b> {html.escape(result.get('scan_engine','nmap'))}</p>
<p><b>Counts:</b> Critical={risk_counts.get('Critical',0)}, High={risk_counts.get('High',0)}, Medium={risk_counts.get('Medium',0)}, Low={risk_counts.get('Low',0)}</p>
</div>
<div class='card'><h2>Open Ports</h2><ul>{open_list}</ul></div>
<div class='card'>
<h2>Vulnerabilities & Fixes</h2>
<table>
<tr><th>Port</th><th>Service</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
{vuln_rows}
</table>
</div>
{warning_section}
{error_section}
<div class='card'><h2>Nmap Raw Output</h2><pre>{html.escape(result.get('nmap_raw_output',''))}</pre></div>
</body>
</html>
"""
        path.write_text(html_body, encoding="utf-8")
