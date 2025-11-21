import os
import json
import subprocess
import sqlite3
import threading
import socket
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, send_file
from apscheduler.schedulers.background import BackgroundScheduler
import logging

app = Flask(__name__)
PORT = int(os.environ.get('PORT', 3000))
DB_FILE = 'security_tools.db'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== DATABASE ====================
def init_db():
    """Khởi tạo database"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY, scan_type TEXT, target TEXT, 
                  result TEXT, status TEXT, created_at TEXT, completed_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY, name TEXT, status TEXT, 
                  output TEXT, created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, timestamp TEXT, message TEXT, level TEXT)''')
    conn.commit()
    conn.close()

def log_action(message, level='INFO'):
    """Lưu log"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('INSERT INTO logs (timestamp, message, level) VALUES (?, ?, ?)', 
              (timestamp, message, level))
    conn.commit()
    conn.close()
    logger.info(f"{level}: {message}")

def save_scan(scan_type, target, result, status='completed'):
    """Lưu kết quả scan"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''INSERT INTO scans 
                 (scan_type, target, result, status, created_at, completed_at) 
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (scan_type, target, result, status, created_at, created_at))
    conn.commit()
    conn.close()

def get_scans(limit=20):
    """Lấy danh sách scan"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
    scans = c.fetchall()
    conn.close()
    return scans

def get_logs(limit=50):
    """Lấy logs"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    logs = c.fetchall()
    conn.close()
    return logs[::-1]

# ==================== SECURITY FUNCTIONS ====================

def port_scan(host, ports="1-1000"):
    """Quét port cơ bản"""
    try:
        log_action(f"Bắt đầu quét port {host}:{ports}")
        result = []
        port_list = []
        
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, min(end + 1, start + 100)))
        else:
            port_list = [int(p.strip()) for p in ports.split(',')]
        
        for port in port_list[:50]:  # Giới hạn 50 port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            res = sock.connect_ex((host, port))
            if res == 0:
                result.append(f"Port {port}: OPEN")
            sock.close()
        
        output = '\n'.join(result) if result else "Không tìm thấy port mở"
        save_scan('port_scan', host, output)
        log_action(f"Hoàn tất quét port {host}")
        return output
    except Exception as e:
        error_msg = f"Lỗi quét port: {str(e)}"
        log_action(error_msg, 'ERROR')
        return error_msg

def dns_lookup(domain):
    """Tra cứu DNS"""
    try:
        log_action(f"Tra cứu DNS: {domain}")
        ip = socket.gethostbyname(domain)
        result = f"Domain: {domain}\nIP Address: {ip}"
        save_scan('dns_lookup', domain, result)
        return result
    except Exception as e:
        error_msg = f"Lỗi DNS: {str(e)}"
        log_action(error_msg, 'ERROR')
        return error_msg

def check_ssl(host):
    """Kiểm tra SSL"""
    try:
        log_action(f"Kiểm tra SSL: {host}")
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{host}:443', '-showcerts'],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout[:500] + "...(xem log)" if len(result.stdout) > 500 else result.stdout
        save_scan('ssl_check', host, output)
        return output if output else "Không thể kết nối SSL"
    except Exception as e:
        error_msg = f"Lỗi SSL: {str(e)}"
        log_action(error_msg, 'ERROR')
        return error_msg

def check_headers(url):
    """Kiểm tra HTTP headers"""
    try:
        log_action(f"Kiểm tra headers: {url}")
        import requests
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = json.dumps(dict(response.headers), indent=2)
        save_scan('http_headers', url, headers)
        return headers
    except Exception as e:
        error_msg = f"Lỗi HTTP: {str(e)}"
        log_action(error_msg, 'ERROR')
        return error_msg

def check_whois(domain):
    """Thông tin WHOIS"""
    try:
        log_action(f"Tra cứu WHOIS: {domain}")
        result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
        output = result.stdout[:1000] + "...(xem log)" if len(result.stdout) > 1000 else result.stdout
        save_scan('whois_lookup', domain, output)
        return output if output else "Không tìm thấy thông tin WHOIS"
    except Exception as e:
        error_msg = f"Lỗi WHOIS: {str(e)}"
        log_action(error_msg, 'ERROR')
        return error_msg

# ==================== BACKGROUND TASKS ====================
scheduler = BackgroundScheduler()

def background_health_check():
    """Health check định kỳ"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_action(f"Background health check - {timestamp}")

scheduler.add_job(func=background_health_check, trigger="interval", minutes=5)
scheduler.start()

# ==================== WEB ROUTES ====================

@app.route('/')
def home():
    """Dashboard chính"""
    html = '''
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Testing Server</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Monaco', 'Courier New', monospace;
                background: #0a0e27;
                color: #0f0;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: #1a1f3a;
                border: 2px solid #0f0;
                border-radius: 8px;
                overflow: hidden;
            }
            .header {
                background: #0f0;
                color: #0a0e27;
                padding: 20px;
                text-align: center;
            }
            .header h1 { font-size: 2em; }
            .content {
                padding: 20px;
            }
            .section {
                margin-bottom: 30px;
                border: 1px solid #0f0;
                padding: 15px;
                border-radius: 5px;
            }
            .section h2 {
                color: #0f0;
                margin-bottom: 15px;
                border-bottom: 1px solid #0f0;
                padding-bottom: 10px;
            }
            .tools-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 10px;
            }
            .tool-btn {
                background: #0f0;
                color: #0a0e27;
                border: none;
                padding: 12px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                transition: all 0.3s;
            }
            .tool-btn:hover { background: #00ff00; transform: scale(1.05); }
            .input-group {
                display: flex;
                gap: 10px;
                margin-bottom: 15px;
            }
            input {
                flex: 1;
                padding: 10px;
                background: #2a2f4a;
                color: #0f0;
                border: 1px solid #0f0;
                border-radius: 4px;
            }
            button {
                background: #0f0;
                color: #0a0e27;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
            }
            button:hover { background: #00ff00; }
            .output {
                background: #0a0e27;
                border: 1px solid #0f0;
                padding: 15px;
                border-radius: 4px;
                max-height: 400px;
                overflow-y: auto;
                font-size: 0.9em;
                margin-top: 15px;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .log-item {
                padding: 8px;
                border-bottom: 1px solid #0f0;
                font-size: 0.85em;
            }
            .log-time { color: #ffff00; font-weight: bold; }
            .log-error { color: #ff6b6b; }
            .log-success { color: #51cf66; }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 10px;
                margin-bottom: 20px;
            }
            .stat-box {
                background: #2a2f4a;
                border: 1px solid #0f0;
                padding: 15px;
                text-align: center;
                border-radius: 4px;
            }
            .stat-box h3 { color: #0f0; font-size: 0.9em; }
            .stat-box p { font-size: 1.8em; color: #00ff00; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔓 Security Testing Server</h1>
                <p>Công cụ Security Researcher chạy 24/7 trên Render</p>
            </div>
            <div class="content">
                <!-- STATS -->
                <div class="stats">
                    <div class="stat-box">
                        <h3>Tổng Scan</h3>
                        <p id="scan-count">0</p>
                    </div>
                    <div class="stat-box">
                        <h3>Status</h3>
                        <p id="status">🟢 Online</p>
                    </div>
                    <div class="stat-box">
                        <h3>Thời gian</h3>
                        <p id="time">--:--:--</p>
                    </div>
                </div>

                <!-- PORT SCANNING -->
                <div class="section">
                    <h2>🔍 Port Scanning</h2>
                    <div class="input-group">
                        <input type="text" id="port-host" placeholder="Host: 192.168.1.1 hoặc example.com">
                        <input type="text" id="port-range" placeholder="Ports: 1-1000 hoặc 80,443,22" value="80,443,22,21,3306">
                        <button onclick="runPortScan()">Quét</button>
                    </div>
                    <div id="port-output" class="output" style="display:none;"></div>
                </div>

                <!-- DNS LOOKUP -->
                <div class="section">
                    <h2>📡 DNS Lookup</h2>
                    <div class="input-group">
                        <input type="text" id="dns-domain" placeholder="Domain: example.com">
                        <button onclick="runDNS()">Tra cứu</button>
                    </div>
                    <div id="dns-output" class="output" style="display:none;"></div>
                </div>

                <!-- SSL CHECK -->
                <div class="section">
                    <h2>🔒 SSL/TLS Certificate</h2>
                    <div class="input-group">
                        <input type="text" id="ssl-host" placeholder="Host: example.com">
                        <button onclick="runSSL()">Kiểm tra</button>
                    </div>
                    <div id="ssl-output" class="output" style="display:none;"></div>
                </div>

                <!-- HTTP HEADERS -->
                <div class="section">
                    <h2>📊 HTTP Headers</h2>
                    <div class="input-group">
                        <input type="text" id="http-url" placeholder="URL: https://example.com">
                        <button onclick="runHeaders()">Kiểm tra</button>
                    </div>
                    <div id="http-output" class="output" style="display:none;"></div>
                </div>

                <!-- WHOIS -->
                <div class="section">
                    <h2>📋 WHOIS Lookup</h2>
                    <div class="input-group">
                        <input type="text" id="whois-domain" placeholder="Domain: example.com">
                        <button onclick="runWHOIS()">Tra cứu</button>
                    </div>
                    <div id="whois-output" class="output" style="display:none;"></div>
                </div>

                <!-- LOGS -->
                <div class="section">
                    <h2>📝 System Logs</h2>
                    <button onclick="refreshLogs()">Làm mới</button>
                    <div id="logs" class="output" style="margin-top: 10px; max-height: 300px;"></div>
                </div>
            </div>
        </div>

        <script>
            function updateTime() {
                const now = new Date();
                document.getElementById('time').textContent = now.toLocaleTimeString('vi-VN');
            }

            function runPortScan() {
                const host = document.getElementById('port-host').value;
                const ports = document.getElementById('port-range').value;
                if (!host) { alert('Nhập host'); return; }
                document.getElementById('port-output').innerHTML = '⏳ Đang quét...';
                document.getElementById('port-output').style.display = 'block';
                fetch('/api/port-scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({host, ports})
                })
                .then(r => r.json())
                .then(d => {
                    document.getElementById('port-output').innerHTML = d.result;
                    refreshStats();
                });
            }

            function runDNS() {
                const domain = document.getElementById('dns-domain').value;
                if (!domain) { alert('Nhập domain'); return; }
                document.getElementById('dns-output').innerHTML = '⏳ Đang tra cứu...';
                document.getElementById('dns-output').style.display = 'block';
                fetch('/api/dns', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({domain})})
                .then(r => r.json()).then(d => { document.getElementById('dns-output').innerHTML = d.result; refreshStats(); });
            }

            function runSSL() {
                const host = document.getElementById('ssl-host').value;
                if (!host) { alert('Nhập host'); return; }
                document.getElementById('ssl-output').innerHTML = '⏳ Đang kiểm tra...';
                document.getElementById('ssl-output').style.display = 'block';
                fetch('/api/ssl', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({host})})
                .then(r => r.json()).then(d => { document.getElementById('ssl-output').innerHTML = d.result; refreshStats(); });
            }

            function runHeaders() {
                const url = document.getElementById('http-url').value;
                if (!url) { alert('Nhập URL'); return; }
                document.getElementById('http-output').innerHTML = '⏳ Đang kiểm tra...';
                document.getElementById('http-output').style.display = 'block';
                fetch('/api/headers', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url})})
                .then(r => r.json()).then(d => { document.getElementById('http-output').innerHTML = d.result; refreshStats(); });
            }

            function runWHOIS() {
                const domain = document.getElementById('whois-domain').value;
                if (!domain) { alert('Nhập domain'); return; }
                document.getElementById('whois-output').innerHTML = '⏳ Đang tra cứu...';
                document.getElementById('whois-output').style.display = 'block';
                fetch('/api/whois', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({domain})})
                .then(r => r.json()).then(d => { document.getElementById('whois-output').innerHTML = d.result; refreshStats(); });
            }

            function refreshLogs() {
                fetch('/api/logs').then(r => r.json()).then(d => {
                    let html = '';
                    d.logs.forEach(log => {
                        const cls = log[3] === 'ERROR' ? 'log-error' : log[3] === 'INFO' ? 'log-success' : '';
                        html += `<div class="log-item"><span class="log-time">[${log[1]}]</span> <span class="${cls}">${log[2]}</span></div>`;
                    });
                    document.getElementById('logs').innerHTML = html;
                });
            }

            function refreshStats() {
                fetch('/api/stats').then(r => r.json()).then(d => {
                    document.getElementById('scan-count').textContent = d.total_scans;
                });
            }

            updateTime();
            setInterval(updateTime, 1000);
            refreshLogs();
            setInterval(refreshLogs, 15000);
            refreshStats();
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/api/port-scan', methods=['POST'])
def api_port_scan():
    data = request.json
    result = port_scan(data.get('host'), data.get('ports', '80,443'))
    return jsonify({'result': result})

@app.route('/api/dns', methods=['POST'])
def api_dns():
    data = request.json
    result = dns_lookup(data.get('domain'))
    return jsonify({'result': result})

@app.route('/api/ssl', methods=['POST'])
def api_ssl():
    data = request.json
    result = check_ssl(data.get('host'))
    return jsonify({'result': result})

@app.route('/api/headers', methods=['POST'])
def api_headers():
    data = request.json
    result = check_headers(data.get('url'))
    return jsonify({'result': result})

@app.route('/api/whois', methods=['POST'])
def api_whois():
    data = request.json
    result = check_whois(data.get('domain'))
    return jsonify({'result': result})

@app.route('/api/logs')
def api_logs():
    logs = get_logs(50)
    return jsonify({'logs': logs})

@app.route('/api/stats')
def api_stats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scans')
    total = c.fetchone()[0]
    conn.close()
    return jsonify({'total_scans': total})

@app.route('/health')
def health():
    return 'OK', 200

if __name__ == '__main__':
    init_db()
    log_action('🚀 Server khởi động')
    print(f"🚀 Security Server chạy trên {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
