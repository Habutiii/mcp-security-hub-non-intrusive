from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
import subprocess
import json
import os
import re
from functools import wraps
import secrets
import requests
import yaml
from packaging import version
import shutil
import sys

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

ALLOWED_TOOLS = [
    "subfinder",
    "naabu",
    "httpx",
    "nuclei",
    "cdncheck",
    "tlsx",
    "ffuf",
    "gobuster",
    "dnsx"
]

DANGEROUS_CHARS = r'[&|;`$(){}\\<>]'

def validate_input(tool, args):
    if not tool or not args:
        return False
    if len(args) > 1000:  # Reasonable limit
        return False
    if re.search(DANGEROUS_CHARS, args):
        return False
    return True

def run_command(tool, args):
    try:
        """
        if not validate_input(tool, args):
            return {
                'stdout': '',
                'stderr': 'Invalid input: contains dangerous characters',
                'returncode': 1
            }
        """
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        cmd = [tool] + args.split()
        process = subprocess.Popen(
            cmd,
            shell=False,  # Security: Prevent shell injection
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            encoding='utf-8',
            errors='replace'
        )
        stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
        
        return {
            'stdout': stdout,
            'stderr': stderr,
            'returncode': process.returncode
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Command timed out'}
    except Exception as e:
        return {'error': 'Internal error'}

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.environ.get('API_KEY'):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/')
def index():
    return render_template('index.html', tools=ALLOWED_TOOLS)

@app.route('/run', methods=['POST'])
# @require_api_key  # Temporarily disabled for testing
def web_run_tool():
    tool = request.form.get('tool', '').lower()
    args = request.form.get('args', '')

    if not tool or not args:
        flash('Tool and arguments are required', 'danger')
        return redirect(url_for('index'))

    if tool not in ALLOWED_TOOLS:
        flash(f'Tool not allowed. Allowed tools: {", ".join(ALLOWED_TOOLS)}', 'danger')
        return redirect(url_for('index'))

    result = run_command(tool, args)
    return render_template('result.html', 
                         tool=tool,
                         args=args,
                         target='',
                         result=result)

@app.route('/api/run', methods=['POST'])
# @require_api_key  # Temporarily disabled for testing
def api_run_tool():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        tool = data.get('tool', '').lower()
        args = data.get('args', '')

        if not tool:
            return jsonify({'error': 'Tool name is required'}), 400

        if tool not in ALLOWED_TOOLS:
            return jsonify({'error': f'Tool not allowed. Allowed tools: {", ".join(ALLOWED_TOOLS)}'}), 400

        return jsonify(run_command(tool, args))
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def check_for_updates():
    try:
        # Get current version from version.txt
        with open('version.txt', 'r', encoding='utf-8-sig') as f:
            current_version = f.read().strip()

        # Get remote version
        response = requests.get('https://mordavid.com/md_versions.yaml')
        if response.status_code != 200:
            print(f"Failed to check for updates: {response.status_code}")
            return

        remote_versions = yaml.safe_load(response.text)
        remote_version = None
        download_url = None
        
        for sw in remote_versions['softwares']:
            if sw['name'] == 'ExternalAttacker-MCP':
                remote_version = sw['version']
                download_url = sw['download']
                break

        if not remote_version or not download_url:
            print("Could not find remote version info")
            return

        # Compare versions
        if version.parse(remote_version) > version.parse(current_version):
            print(f"New version available: {remote_version}")
            
            # Update MCP file
            response = requests.get(download_url)
            if response.status_code == 200:
                # Backup current MCP file
                shutil.copy2('ExternalAttacker-MCP.py', 'ExternalAttacker-MCP.py.bak')
                
                # Write new MCP version
                with open('ExternalAttacker-MCP.py', 'wb') as f:
                    f.write(response.content)
                print("Successfully updated MCP to new version")
            else:
                print(f"Failed to download MCP update: {response.status_code}")
                return

            # Update App file
            app_url = download_url.replace('ExternalAttacker-MCP.py', 'ExternalAttacker-App.py')
            response = requests.get(app_url)
            if response.status_code == 200:
                # Backup current App file
                shutil.copy2('ExternalAttacker-App.py', 'ExternalAttacker-App.py.bak')
                
                # Write new App version
                with open('ExternalAttacker-App.py', 'wb') as f:
                    f.write(response.content)
                print("Successfully updated App to new version")
            else:
                print(f"Failed to download App update: {response.status_code}")
                return

            # Update version.txt
            with open('version.txt', 'w', encoding='utf-8-sig') as f:
                f.write(remote_version)
            print(f"Updated version.txt to {remote_version}")

            print("All components updated successfully")
            # Restart the application to apply updates
            os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(f"Update check failed: {str(e)}")

if __name__ == '__main__':
    print("Checking for updates...")
    check_for_updates()
    debug = os.environ.get('FLASK_ENV') == 'development'
    host = '127.0.0.1' if debug else '0.0.0.0'
    app.run(debug=debug, host=host, port=6991) 