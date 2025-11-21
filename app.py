import os
import json
import subprocess
import sqlite3
import socket
import shlex
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
import logging

app = Flask(__name__)
PORT = int(os.environ.get('PORT', 10000))
DB_FILE = 'terminal.db'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== DATABASE ====================
def init_db():
    """Khởi tạo database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS commands
                     (id INTEGER PRIMARY KEY, command TEXT, output TEXT, 
                      status TEXT, timestamp TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs
                     (id INTEGER PRIMARY KEY, timestamp TEXT, message TEXT, level TEXT)''')
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"DB init error: {str(e)}")

def log_action(message, level='INFO'):
    """Lưu log"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('INSERT INTO logs (timestamp, message, level) VALUES (?, ?, ?)', 
                  (timestamp, message, level))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Log error: {str(e)}")

def save_command(command, output, status='success'):
    """Lưu lịch sử lệnh"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('INSERT INTO commands (command, output, status, timestamp) VALUES (?, ?, ?, ?)',
                  (command, output, status, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Save command error: {str(e)}")

def get_history(limit=20):
    """Lấy lịch sử lệnh"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT command, output, timestamp FROM commands ORDER BY id DESC LIMIT ?', (limit,))
        history = c.fetchall()
        conn.close()
        return history[::-1]
    except Exception as e:
        logger.error(f"Get history error: {str(e)}")
        return []

# ==================== COMMAND EXECUTION ====================

# Danh sách lệnh được phép (whitelist)
ALLOWED_COMMANDS = {
    # System info
    'uname', 'hostname', 'whoami', 'uptime', 'date', 'pwd', 'ls', 'cat', 'echo',
    # Network
    'ping', 'curl', 'wget', 'dig', 'nslookup', 'host', 'traceroute', 'netstat', 'ss',
    # Security tools
    'nmap', 'whois', 'nikto', 'sqlmap', 'hydra', 'john',
    # File operations
    'find', 'grep', 'head', 'tail', 'wc',
    # Process
    'ps', 'top', 'htop', 'kill',
    # Python
    'python', 'python3', 'pip', 'pip3'
}

def execute_command(command):
    """Thực thi lệnh Linux"""
    try:
        # Log lệnh
        log_action(f"Executing: {command}")
        
        # Parse lệnh
        parts = shlex.split(command)
        if not parts:
            return "Error: Empty command"
        
        base_cmd = parts[0]
        
        # Kiểm tra lệnh có được phép không
        if base_cmd not in ALLOWED_COMMANDS:
            return f"❌ Command '{base_cmd}' not allowed. Use 'help' to see available commands."
        
        # Giới hạn độ dài output
        timeout = 10
        
        # Thực thi lệnh
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd='/tmp'  # Chạy trong thư mục an toàn
        )
        
        output = result.stdout if result.stdout else result.stderr
        if not output:
            output = "✓ Command executed successfully (no output)"
        
        # Giới hạn output 5000 ký tự
        if len(output) > 5000:
            output = output[:5000] + "\n\n... (output truncated)"
        
        # Lưu vào database
        save_command(command, output, 'success' if result.returncode == 0 else 'error')
        
        return output
        
    except subprocess.TimeoutExpired:
        error = f"⏱️ Command timeout after {timeout}s"
        save_command(command, error, 'timeout')
        return error
    except Exception as e:
        error = f"❌ Error: {str(e)}"
        save_command(command, error, 'error')
        log_action(error, 'ERROR')
        return error

def get_help():
    """Hiển thị help"""
    help_text = """
🔐 LINUX TERMINAL - WHITE HAT SECURITY TOOLS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 SYSTEM COMMANDS:
  uname -a          - System information
  hostname          - Show hostname
  whoami            - Current user
  uptime            - System uptime
  date              - Current date/time
  pwd               - Current directory
  ls -la            - List files

🌐 NETWORK COMMANDS:
  ping google.com           - Ping test
  curl https://example.com  - HTTP request
  dig example.com           - DNS lookup
  nslookup example.com      - DNS query
  whois example.com         - Domain info
  netstat -tuln             - Network connections

🔒 SECURITY TOOLS:
  nmap -sV target.com       - Port scanning
  nikto -h target.com       - Web vulnerability scanner
  sqlmap -u "url"           - SQL injection testing
  hydra -l user -P pass.txt host  - Brute force

📁 FILE OPERATIONS:
  cat /etc/os-release       - Read file
  grep "text" file          - Search in file
  find / -name "file"       - Find file
  head -n 10 file           - First 10 lines
  tail -f log.txt           - Follow log file

💻 PROCESS COMMANDS:
  ps aux                    - List processes
  top                       - Process monitor
  kill -9 PID               - Kill process

🐍 PYTHON:
  python3 --version         - Python version
  pip3 list                 - List packages

⚙️ SPECIAL COMMANDS:
  help                      - Show this help
  clear                     - Clear terminal
  history                   - Command history
  exit                      - Close terminal

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  Chỉ sử dụng cho mục đích hợp pháp!
    """
    return help_text

# ==================== BACKGROUND SCHEDULER ====================
scheduler = BackgroundScheduler()

def background_health():
    """Health check"""
    log_action("Background health check")

scheduler.add_job(func=background_health, trigger="interval", minutes=5)
scheduler.start()

# ==================== WEB ROUTES ====================

@app.route('/')
def home():
    """Terminal UI"""
    html = '''
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Terminal - White Hat Security</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Ubuntu Mono', 'Courier New', monospace;
            background: #0a0e27;
            color: #0f0;
            height: 100vh;
            overflow: hidden;
        }
        
        .container {
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        .header {
            background: linear-gradient(90deg, #0f0 0%, #0a0 100%);
            color: #000;
            padding: 8px 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f0;
            font-size: 0.9em;
        }
        
        .header h1 {
            font-size: 1em;
            font-weight: bold;
        }
        
        .status {
            display: flex;
            gap: 10px;
            font-size: 0.85em;
        }
        
        .status span {
            background: #000;
            color: #0f0;
            padding: 3px 8px;
            border-radius: 3px;
        }
        
        .terminal {
            flex: 1;
            background: #000;
            padding: 20px;
            overflow-y: auto;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .terminal::-webkit-scrollbar {
            width: 10px;
        }
        
        .terminal::-webkit-scrollbar-track {
            background: #0a0e27;
        }
        
        .terminal::-webkit-scrollbar-thumb {
            background: #0f0;
            border-radius: 5px;
        }
        
        .line {
            margin: 5px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .prompt {
            color: #0f0;
            font-weight: bold;
        }
        
        .output {
            color: #00ff00;
            margin-left: 0;
            padding: 5px 0;
        }
        
        .error {
            color: #ff6b6b;
        }
        
        .success {
            color: #51cf66;
        }
        
        .info {
            color: #339af0;
        }
        
        .warning {
            color: #ffd43b;
        }
        
        .input-container {
            display: flex;
            align-items: center;
            padding: 15px 20px;
            background: #1a1f3a;
            border-top: 2px solid #0f0;
        }
        
        .prompt-text {
            color: #0f0;
            font-weight: bold;
            margin-right: 10px;
            white-space: nowrap;
        }
        
        #commandInput {
            flex: 1;
            background: #000;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 10px;
            font-family: 'Ubuntu Mono', 'Courier New', monospace;
            font-size: 14px;
            outline: none;
            border-radius: 3px;
        }
        
        #commandInput:focus {
            border-color: #00ff00;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
        }
        
        .btn-execute {
            background: #0f0;
            color: #000;
            border: none;
            padding: 10px 20px;
            margin-left: 10px;
            cursor: pointer;
            font-weight: bold;
            border-radius: 3px;
            font-family: 'Ubuntu Mono', monospace;
            transition: all 0.3s;
        }
        
        .btn-execute:hover {
            background: #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.5);
        }
        
        .toolbar {
            background: #1a1f3a;
            padding: 8px 15px;
            display: flex;
            gap: 10px;
            border-bottom: 1px solid #0f0;
        }
        
        .toolbar button {
            background: #0f0;
            color: #000;
            border: none;
            padding: 5px 15px;
            cursor: pointer;
            font-weight: bold;
            border-radius: 3px;
            font-size: 0.85em;
            transition: all 0.3s;
        }
        
        .toolbar button:hover {
            background: #00ff00;
            transform: scale(1.05);
        }
        
        .cursor {
            display: inline-block;
            width: 8px;
            height: 16px;
            background: #0f0;
            animation: blink 1s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        
        .boot-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #000;
            color: #0f0;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            font-family: 'Ubuntu Mono', monospace;
        }
        
        .boot-text {
            font-size: 1.2em;
            margin: 10px 0;
        }
        
        .loading-bar {
            width: 300px;
            height: 20px;
            border: 2px solid #0f0;
            margin-top: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .loading-fill {
            height: 100%;
            background: #0f0;
            width: 0;
            animation: load 3s forwards;
        }
        
        @keyframes load {
            to { width: 100%; }
        }
    </style>
</head>
<body>
    <div id="bootScreen" class="boot-screen">
        <div class="boot-text">🐧 BOOTING LINUX SYSTEM...</div>
        <div class="boot-text">White Hat Security Terminal v1.0</div>
        <div class="loading-bar">
            <div class="loading-fill"></div>
        </div>
    </div>

    <div class="container" style="display: none;" id="mainContainer">
        <div class="header">
            <h1>🐧 LINUX TERMINAL - WHITE HAT SECURITY</h1>
            <div class="status">
                <span>👤 root@security</span>
                <span id="time">--:--:--</span>
                <span>🟢 ONLINE</span>
            </div>
        </div>
        
        <div class="toolbar">
            <button onclick="runCommand('help')">📖 Help</button>
            <button onclick="runCommand('uname -a')">💻 System</button>
            <button onclick="runCommand('ls -la')">📁 Files</button>
            <button onclick="runCommand('ps aux')">⚙️ Process</button>
            <button onclick="clearTerminal()">🗑️ Clear</button>
            <button onclick="showHistory()">📜 History</button>
        </div>
        
        <div class="terminal" id="terminal">
            <div class="line success">
╔════════════════════════════════════════════════════════════╗
║  🔐 WHITE HAT SECURITY TERMINAL - LINUX PENTESTING TOOLS  ║
║  ⚠️  CHỈ SỬ DỤNG CHO MỤC ĐÍCH HỢP PHÁP                    ║
║  📝 Type 'help' để xem danh sách lệnh                      ║
╚════════════════════════════════════════════════════════════╝
            </div>
        </div>
        
        <div class="input-container">
            <span class="prompt-text">root@security:~$</span>
            <input type="text" id="commandInput" placeholder="Nhập lệnh Linux... (VD: ls -la, ping google.com, nmap, help)" autofocus>
            <button class="btn-execute" onclick="executeCommand()">▶ Execute</button>
        </div>
    </div>

    <script>
        // Boot animation
        setTimeout(() => {
            document.getElementById('bootScreen').style.display = 'none';
            document.getElementById('mainContainer').style.display = 'flex';
            document.getElementById('commandInput').focus();
        }, 3000);

        let commandHistory = [];
        let historyIndex = -1;

        function updateTime() {
            const now = new Date();
            document.getElementById('time').textContent = now.toLocaleTimeString('vi-VN');
        }
        setInterval(updateTime, 1000);
        updateTime();

        function addLine(text, className = '') {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'line ' + className;
            line.textContent = text;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }

        function addPrompt(command) {
            addLine(`root@security:~$ ${command}`, 'prompt');
        }

        function addOutput(text, className = 'output') {
            const terminal = document.getElementById('terminal');
            const output = document.createElement('div');
            output.className = 'line ' + className;
            output.textContent = text;
            terminal.appendChild(output);
            terminal.scrollTop = terminal.scrollHeight;
        }

        function clearTerminal() {
            const terminal = document.getElementById('terminal');
            terminal.innerHTML = `
                <div class="line success">
╔════════════════════════════════════════════════════════════╗
║  🔐 WHITE HAT SECURITY TERMINAL - LINUX PENTESTING TOOLS  ║
║  ⚠️  CHỈ SỬ DỤNG CHO MỤC ĐÍCH HỢP PHÁP                    ║
║  📝 Type 'help' để xem danh sách lệnh                      ║
╚════════════════════════════════════════════════════════════╝
                </div>
            `;
        }

        function runCommand(cmd) {
            document.getElementById('commandInput').value = cmd;
            executeCommand();
        }

        async function executeCommand() {
            const input = document.getElementById('commandInput');
            const command = input.value.trim();
            
            if (!command) return;
            
            // Special commands
            if (command === 'clear' || command === 'cls') {
                clearTerminal();
                input.value = '';
                return;
            }
            
            if (command === 'exit') {
                addPrompt(command);
                addOutput('👋 Goodbye! Refresh page to restart.', 'warning');
                input.disabled = true;
                return;
            }
            
            // Add to history
            commandHistory.unshift(command);
            historyIndex = -1;
            
            // Show command
            addPrompt(command);
            addOutput('⏳ Executing...', 'info');
            
            try {
                const response = await fetch('/api/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command })
                });
                
                const data = await response.json();
                
                // Remove loading message
                const terminal = document.getElementById('terminal');
                terminal.removeChild(terminal.lastChild);
                
                // Show output
                const outputClass = data.status === 'success' ? 'output' : 'error';
                addOutput(data.output, outputClass);
                
            } catch (error) {
                addOutput(`❌ Request error: ${error.message}`, 'error');
            }
            
            input.value = '';
            input.focus();
        }

        async function showHistory() {
            try {
                const response = await fetch('/api/history');
                const data = await response.json();
                
                addLine('━━━━━━━━━━━━━━━ COMMAND HISTORY ━━━━━━━━━━━━━━━', 'info');
                data.history.forEach((item, idx) => {
                    addLine(`[${item[2]}] ${item[0]}`, 'output');
                });
                addLine('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'info');
            } catch (error) {
                addOutput('❌ Failed to load history', 'error');
            }
        }

        // Enter key handler
        document.getElementById('commandInput').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                executeCommand();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    document.getElementById('commandInput').value = commandHistory[historyIndex];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    document.getElementById('commandInput').value = commandHistory[historyIndex];
                } else {
                    historyIndex = -1;
                    document.getElementById('commandInput').value = '';
                }
            }
        });
    </script>
</body>
</html>
    '''
    return render_template_string(html)

@app.route('/api/execute', methods=['POST'])
def api_execute():
    """API thực thi lệnh"""
    try:
        data = request.json
        command = data.get('command', '').strip()
        
        if not command:
            return jsonify({'output': 'Error: Empty command', 'status': 'error'})
        
        # Special commands
        if command == 'help':
            output = get_help()
            return jsonify({'output': output, 'status': 'success'})
        
        if command == 'history':
            history = get_history()
            output = '\n'.join([f"[{h[2]}] {h[0]}" for h in history])
            return jsonify({'output': output, 'status': 'success'})
        
        # Execute command
        output = execute_command(command)
        status = 'error' if output.startswith('❌') or output.startswith('⏱️') else 'success'
        
        return jsonify({'output': output, 'status': status})
        
    except Exception as e:
        return jsonify({'output': f'❌ Server error: {str(e)}', 'status': 'error'})

@app.route('/api/history')
def api_history():
    """API lấy lịch sử"""
    try:
        history = get_history(30)
        return jsonify({'history': history})
    except Exception as e:
        return jsonify({'history': [], 'error': str(e)})

@app.route('/health')
def health():
    return 'OK', 200

if __name__ == '__main__':
    try:
        init_db()
        log_action('🐧 Linux Terminal Server started')
        print(f"🐧 Linux Terminal chạy trên port {PORT}")
        app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
    except Exception as e:
        logger.error(f"Failed to start: {str(e)}")
        raise
