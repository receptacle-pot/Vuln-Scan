# Zaalima Real-Time Vulnerability Scanner (Flask + Nmap)

A defensive lab scanner web app that performs:
- Real-time **Nmap-driven** TCP port scanning for localhost/private targets
- Lightweight network neighbor discovery
- Local vulnerability mapping with severity and CVSS estimates
- Risk prioritization (Critical/High/Medium/Low)
- HTML report export after each scan
- Pie chart visualization for vulnerability distribution

## Requirements
- Python 3.10+
- Nmap installed and available on PATH (`nmap --version`)

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Scan behavior
The backend runs:

```bash
nmap -Pn --top-ports <N> <target>
```

Set `N=1000` to match a typical default port sweep similar to `nmap <target>`.

## Safety
This tool intentionally restricts targets to `localhost` and private RFC1918 IP space for legal/ethical defensive testing in lab environments.