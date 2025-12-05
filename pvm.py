"""
Full-featured Proxy Web Panel
- FastAPI backend with server-side Jinja2 templates (single-file for simplicity)
- Local JSON database: proxy_users.json
- Admin login (simple password from env ADMIN_PASS, default: 'admin')
- Create proxy users (username/password/port)
- Apply per-user bandwidth using 3proxy bandlim* rules and optional `tc` (uses `tc` only if available)
- Run server-side speedtest using speedtest-cli (optional)

Security notes:
- This is a starter panel. For production: enable HTTPS, strong auth, CSRF protection, run as non-root or restrict commands, sanitize inputs, and audit subprocess calls.

How to run (quick):
1) Install dependencies:
   pip install -r requirements.txt
   Or manually: pip install fastapi uvicorn jinja2 python-multipart
   Optional: pip install speedtest-cli
2) Ensure 3proxy is installed. The config path defaults to /etc/3proxy/3proxy.cfg but can be set via THREEPROXY_CFG environment variable.
3) Set admin password (recommended):
   export ADMIN_PASS="your_strong_password"
4) Run:
   sudo python3 pvm.py
5) Open: http://0.0.0.0:8000

"""

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_303_SEE_OTHER
import os, json, uuid, subprocess
from datetime import datetime
import secrets
import threading

# ---------- CONFIG ----------
THREEPROXY_CFG = os.environ.get('THREEPROXY_CFG', "/etc/3proxy/3proxy.cfg")
DB_FILE = "proxy_users.json"
TEMPLATES_DIR = "templates"
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin')
HOST = "0.0.0.0"
PORT = 8000
MANAGED_START = "# --- MANAGED BY PROXY PANEL START ---"
MANAGED_END = "# --- MANAGED BY PROXY PANEL END ---"

# Ensure templates dir
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# ---------- SIMPLE DB ----------
if not os.path.exists(DB_FILE):
    with open(DB_FILE, 'w') as f:
        json.dump({}, f)


def db_read():
    with open(DB_FILE, 'r') as f:
        return json.load(f)


def db_write(d):
    with open(DB_FILE, 'w') as f:
        json.dump(d, f, indent=2)

# ---------- TEMPLATES (simple bootstrap UI) ----------
INDEX_HTML = '''<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Panel</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Proxy Panel</h2>
    <div>
      <a class="btn btn-primary" href="/create">Create Proxy</a>
      <a class="btn btn-outline-secondary" href="/users">Users</a>
      <a class="btn btn-outline-dark" href="/logout">Logout</a>
    </div>
  </div>
  <div class="card p-4 mb-4">
    <h5>Server Info</h5>
    <p>Host: <strong>{{ host }}</strong> | Time: {{ now }}</p>
    <p>3proxy config: <code>{{ cfg_path }}</code></p>
  </div>
  <div class="row">
    <div class="col-md-6">
      <div class="card p-3 mb-3">
        <h6>Quick Actions</h6>
        <ul>
          <li>Create proxy user with username/password/port.</li>
          <li>Set per-user bandwidth limits and apply.</li>
        </ul>
      </div>
    </div>
  </div>
</div>
</body>
</html>
'''

CREATE_HTML = '''<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Create Proxy</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
  <a href="/" class="btn btn-link">&larr; Back</a>
  <div class="card p-4">
    <h4>Create Proxy</h4>
    <form method="post" action="/create">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input class="form-control" name="username" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Password</label>
        <input class="form-control" name="password" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Port</label>
        <input class="form-control" name="port" value="3128" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Download Limit (Mbps, 0 = no limit)</label>
        <input class="form-control" name="dl_limit" value="0">
      </div>
      <div class="mb-3">
        <label class="form-label">Upload Limit (Mbps, 0 = no limit)</label>
        <input class="form-control" name="ul_limit" value="0">
      </div>
      <button class="btn btn-success" type="submit">Create Proxy</button>
    </form>
  </div>
</div>
</body>
</html>
'''

USERS_HTML = '''<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Users</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
  <a href="/" class="btn btn-link">&larr; Back</a>
  <h3>Proxy Users</h3>
  <table class="table">
    <thead><tr><th>Username</th><th>Port</th><th>DL(Mbps)</th><th>UL(Mbps)</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody>
    {% for u in users %}
      <tr>
        <td>{{ u.username }}</td>
        <td>{{ u.port }}</td>
        <td>{{ u.dl_limit or 0 }}</td>
        <td>{{ u.ul_limit or 0 }}</td>
        <td>{{ u.created }}</td>
        <td>
          <form method="post" action="/user/{{ u.id }}/apply" style="display:inline">
            <button class="btn btn-sm btn-primary">Apply Limits</button>
          </form>
          <a href="/user/{{ u.id }}/speedtest" target="_blank" class="btn btn-sm btn-info" title="Run Speed Test">
            <i class="bi bi-speedometer2"></i> Speedtest
          </a>
          <form method="post" action="/user/{{ u.id }}/delete" style="display:inline" onsubmit="return confirm('Delete user?')">
            <button class="btn btn-sm btn-danger">Delete</button>
          </form>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</body>
</html>
'''

LOGIN_HTML = '''<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
  <div class="row justify-content-center">
    <div class="col-md-4">
      <div class="card p-4">
        <h4>Admin Login</h4>
        <form method="post" action="/login">
          <div class="mb-3"><label>Admin Password</label>
            <input name="password" type="password" class="form-control" required></div>
          <button class="btn btn-primary" type="submit">Login</button>
        </form>
      </div>
    </div>
  </div>
</div>
</body>
</html>
'''

# write templates
with open(os.path.join(TEMPLATES_DIR, 'index.html'), 'w') as f:
    f.write(INDEX_HTML)
with open(os.path.join(TEMPLATES_DIR, 'create.html'), 'w') as f:
    f.write(CREATE_HTML)
with open(os.path.join(TEMPLATES_DIR, 'users.html'), 'w') as f:
    f.write(USERS_HTML)
with open(os.path.join(TEMPLATES_DIR, 'login.html'), 'w') as f:
    f.write(LOGIN_HTML)

# ---------- APP SETUP ----------
app = FastAPI()
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# simple session store (not persistent) - maps token->true
SESSIONS = {}

# Speedtest results cache (in-memory)
SPEEDTEST_RESULTS = {}

# ---------- HELPERS ----------

def ensure_3proxy_cfg():
    if not os.path.exists(THREEPROXY_CFG):
        # create directory if it doesn't exist
        cfg_dir = os.path.dirname(THREEPROXY_CFG)
        if cfg_dir:
            os.makedirs(cfg_dir, exist_ok=True)
        # create a basic config
        base = """auth strong
users
proxy -n
flush
"""
        try:
            with open(THREEPROXY_CFG, 'w') as f:
                f.write(base)
        except (IOError, OSError) as e:
            print(f"Warning: Could not create 3proxy config file at {THREEPROXY_CFG}: {e}")
            raise


def read_managed():
    ensure_3proxy_cfg()
    with open(THREEPROXY_CFG, 'r') as f:
        content = f.read()
    if MANAGED_START in content and MANAGED_END in content:
        inner = content.split(MANAGED_START,1)[1].split(MANAGED_END,1)[0]
        return inner.strip().splitlines()
    return []


def write_managed(lines):
    ensure_3proxy_cfg()
    with open(THREEPROXY_CFG, 'r') as f:
        content = f.read()
    if MANAGED_START in content and MANAGED_END in content:
        before, rest = content.split(MANAGED_START,1)
        _old, after = rest.split(MANAGED_END,1)
        new = before + MANAGED_START + '\n' + '\n'.join(lines) + '\n' + MANAGED_END + after
    else:
        new = content + '\n\n' + MANAGED_START + '\n' + '\n'.join(lines) + '\n' + MANAGED_END + '\n'
    with open(THREEPROXY_CFG, 'w') as f:
        f.write(new)


def restart_3proxy():
    # try systemctl, fallback to service
    for cmd in (["systemctl","restart","3proxy"], ["service","3proxy","restart"]):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if p.returncode == 0:
                return True
        except Exception:
            pass
    return False


def apply_tc_limit(port, dl_mbps, ul_mbps):
    # requires root
    # we will shape by creating HTB qdisc per port on eth0 (assumes eth0)
    dev = os.environ.get('NET_DEV', 'eth0')
    # remove old filter for the port if exists
    try:
        # create root qdisc if not exists
        subprocess.run(["tc","qdisc","add","dev",dev,"root","handle","1:","htb"], check=False)
        classid = f"1:{1000+int(port)}"
        rate = f"{int(dl_mbps)}mbit" if dl_mbps>0 else "1000mbit"
        ceil = rate
        subprocess.run(["tc","class","add","dev",dev,"parent","1:","classid",classid,"htb","rate",rate,"ceil",ceil], check=False)
        # filter by destination port (outgoing)
        subprocess.run(["tc","filter","add","dev",dev,"protocol","ip","parent","1:","prio","1","u32","match","ip","dport",str(port),"0xffff","flowid",classid], check=False)
        return True
    except Exception as e:
        print("tc error", e)
        return False

# ---------- AUTH DEPENDENCY ----------

def require_login(request: Request):
    token = request.cookies.get('session')
    if not token or token not in SESSIONS:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return True

def get_server_ip(request: Request = None):
    """Get server public IP address or domain name - Auto detect"""
    # Cache IP to avoid repeated lookups
    if not hasattr(get_server_ip, '_cached_ip'):
        get_server_ip._cached_ip = None
        get_server_ip._cache_time = 0
    
    # Use cached IP if less than 5 minutes old
    import time
    if get_server_ip._cached_ip and (time.time() - get_server_ip._cache_time) < 300:
        return get_server_ip._cached_ip
    
    try:
        # Priority 1: Environment variable override
        env_ip = os.environ.get('SERVER_IP', '').strip()
        if env_ip:
            get_server_ip._cached_ip = env_ip
            get_server_ip._cache_time = time.time()
            return env_ip
        
        # Priority 2: Get from request headers (domain name from Nginx/VPS)
        if request:
            # X-Forwarded-Host (from reverse proxy like Nginx)
            forwarded_host = request.headers.get('x-forwarded-host', '').split(':')[0].strip()
            if forwarded_host and forwarded_host not in ['0.0.0.0', 'localhost', '127.0.0.1', '::1', '']:
                get_server_ip._cached_ip = forwarded_host
                get_server_ip._cache_time = time.time()
                return forwarded_host
            
            # Host header
            host = request.headers.get('host', '').split(':')[0].strip()
            if host and host not in ['0.0.0.0', 'localhost', '127.0.0.1', '::1', ''] and not host.startswith('127.'):
                get_server_ip._cached_ip = host
                get_server_ip._cache_time = time.time()
                return host
        
        # Priority 3: Auto-detect public IP from multiple services
        ip_services = [
            'https://api.ipify.org',
            'https://ifconfig.me',
            'https://icanhazip.com',
            'https://ipinfo.io/ip',
            'https://checkip.amazonaws.com',
        ]
        
        for service in ip_services:
            try:
                # Try with curl first
                result = subprocess.run(
                    ['curl', '-s', '--max-time', '5', '--connect-timeout', '3', service],
                    capture_output=True,
                    text=True,
                    timeout=6
                )
                if result.returncode == 0:
                    ip = result.stdout.strip()
                    if ip and '.' in ip:
                        parts = ip.split('.')
                        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                            get_server_ip._cached_ip = ip
                            get_server_ip._cache_time = time.time()
                            return ip
            except:
                continue
        
        # Priority 4: Try Python requests if available (more reliable)
        try:
            import urllib.request
            import urllib.error
            for service in ['https://api.ipify.org', 'https://ifconfig.me']:
                try:
                    with urllib.request.urlopen(service, timeout=5) as response:
                        ip = response.read().decode('utf-8').strip()
                        if ip and '.' in ip:
                            parts = ip.split('.')
                            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                                get_server_ip._cached_ip = ip
                                get_server_ip._cache_time = time.time()
                                return ip
                except:
                    continue
        except:
            pass
        
        # Priority 5: Get local network IP as fallback
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and ip not in ['127.0.0.1', '0.0.0.0']:
                get_server_ip._cached_ip = ip
                get_server_ip._cache_time = time.time()
                return ip
        except:
            pass
            
    except Exception as e:
        print(f"Error getting server IP: {e}")
    
    # Return cached value if available, otherwise unknown
    if get_server_ip._cached_ip:
        return get_server_ip._cached_ip
    
    return "UNKNOWN_IP"

# ---------- ROUTES ----------
@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    try:
        require_login(request)
    except HTTPException as e:
        return RedirectResponse(url='/login')
    now = datetime.utcnow().isoformat() + 'Z'
    db = db_read()
    user_count = len(db)
    server_ip = get_server_ip(request)
    return templates.TemplateResponse('index.html', { 
        'request': request, 
        'host': HOST, 
        'server_ip': server_ip,
        'now': now, 
        'cfg_path': THREEPROXY_CFG,
        'user_count': user_count
    })

@app.get('/login', response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse('login.html', { 'request': request })

@app.post('/login')
async def login_post(request: Request, password: str = Form(...)):
    if secrets.compare_digest(password, ADMIN_PASS):
        token = str(uuid.uuid4())
        SESSIONS[token] = True
        resp = RedirectResponse(url='/', status_code=HTTP_303_SEE_OTHER)
        resp.set_cookie('session', token, httponly=True)
        return resp
    return RedirectResponse(url='/login')

@app.get('/logout')
async def logout(request: Request):
    token = request.cookies.get('session')
    if token in SESSIONS:
        del SESSIONS[token]
    resp = RedirectResponse(url='/login')
    resp.delete_cookie('session')
    return resp

@app.get('/create', response_class=HTMLResponse)
async def create_get(request: Request):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    return templates.TemplateResponse('create.html', { 'request': request })

@app.post('/create')
async def create_post(request: Request, username: str = Form(...), password: str = Form(...), port: int = Form(...), proxy_type: str = Form('both'), dl_limit: float = Form(0.0), ul_limit: float = Form(0.0)):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')

    # validate port
    if not (1024 <= port <= 65535):
        raise HTTPException(status_code=400, detail='Port must be between 1024 and 65535')

    # validate proxy type
    if proxy_type not in ['http', 'socks5', 'both']:
        proxy_type = 'both'

    # check for duplicate port or username
    db = db_read()
    for existing_user in db.values():
        existing_port = existing_user.get('port')
        existing_type = existing_user.get('proxy_type', 'http')
        # Check for port conflicts
        if existing_port == port:
            raise HTTPException(status_code=400, detail=f'Port {port} is already in use')
        # Check if SOCKS5 port (port+1) conflicts when 'both' is selected
        if proxy_type == 'both' and existing_type == 'both' and existing_port == port + 1:
            raise HTTPException(status_code=400, detail=f'Port {port+1} is already in use (SOCKS5 port conflict)')
        if proxy_type == 'both' and existing_port == port + 1:
            raise HTTPException(status_code=400, detail=f'Port {port+1} is already in use')
        # Check if new SOCKS5 port conflicts with existing
        if existing_type == 'both' and existing_port == port - 1:
            raise HTTPException(status_code=400, detail=f'Port {port} conflicts with existing SOCKS5 port {port-1}')
        if existing_user.get('username') == username:
            raise HTTPException(status_code=400, detail=f'Username {username} already exists')

    uid = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + 'Z'
    entry = {
        'id': uid,
        'username': username,
        'password': password,
        'port': port,
        'proxy_type': proxy_type,
        'created': now,
        'dl_limit': float(dl_limit),
        'ul_limit': float(ul_limit),
        'last_speed': None
    }
    # save to db
    db[uid] = entry
    db_write(db)

    # update 3proxy cfg
    try:
        add_user_to_3proxy(entry)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Failed to add to 3proxy: {e}')

    # apply limits via tc if requested
    if entry['dl_limit']>0:
        apply_tc_limit(entry['port'], entry['dl_limit'], entry['ul_limit'])

    return RedirectResponse(url='/users', status_code=HTTP_303_SEE_OTHER)

@app.get('/users', response_class=HTMLResponse)
async def users_get(request: Request):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    db = db_read()
    users = list(db.values())
    # Get server IP/host
    server_host = get_server_ip(request)
    return templates.TemplateResponse('users.html', { 
        'request': request, 
        'users': users,
        'server_host': server_host
    })

@app.get('/user/{user_id}/connection', response_class=HTMLResponse)
async def user_connection(user_id: str, request: Request):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    db = db_read()
    if user_id not in db:
        raise HTTPException(status_code=404, detail='User not found')
    entry = db[user_id]
    # Get server IP/host
    server_host = get_server_ip(request)
    # Check if 3proxy is running
    proxy_status = "Unknown"
    try:
        result = subprocess.run(['systemctl', 'is-active', '3proxy'], 
                              capture_output=True, text=True, timeout=2)
        proxy_status = "Running" if result.returncode == 0 else "Not Running"
    except:
        pass
    return templates.TemplateResponse('connection.html', {
        'request': request,
        'user': entry,
        'server_host': server_host,
        'proxy_status': proxy_status
    })

@app.get('/user/{user_id}/test', response_class=HTMLResponse)
async def user_test(user_id: str, request: Request):
    """Test if proxy connection works"""
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    db = db_read()
    if user_id not in db:
        raise HTTPException(status_code=404, detail='User not found')
    entry = db[user_id]
    
    # Test proxy connection
    test_result = {
        'success': False,
        'message': '',
        'details': {}
    }
    
    try:
        # Check if port is listening
        result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=5)
        port_listening = f':{entry["port"]}' in result.stdout
        
        # Check if 3proxy is running
        result = subprocess.run(['systemctl', 'is-active', '3proxy'], 
                              capture_output=True, text=True, timeout=2)
        proxy_running = result.returncode == 0
        
        if proxy_running and port_listening:
            test_result['success'] = True
            test_result['message'] = 'Proxy is running and port is open'
        elif proxy_running:
            test_result['message'] = '3proxy is running but port may not be listening'
        else:
            test_result['message'] = '3proxy service is not running'
            
        test_result['details'] = {
            'proxy_running': proxy_running,
            'port_listening': port_listening,
            'port': entry['port']
        }
    except Exception as e:
        test_result['message'] = f'Test error: {str(e)}'
    
    return templates.TemplateResponse('test.html', {
        'request': request,
        'user': entry,
        'test_result': test_result
    })

@app.post('/user/{user_id}/apply')
async def user_apply(user_id: str, request: Request):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    db = db_read()
    if user_id not in db:
        raise HTTPException(status_code=404, detail='User not found')
    entry = db[user_id]
    # regenerate 3proxy managed block with updated limits
    add_user_to_3proxy(entry, replace=True)
    if entry.get('dl_limit',0)>0:
        apply_tc_limit(entry['port'], entry['dl_limit'], entry.get('ul_limit',0))
    return RedirectResponse(url='/users', status_code=HTTP_303_SEE_OTHER)

@app.post('/user/{user_id}/delete')
async def user_delete(user_id: str, request: Request):
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    db = db_read()
    if user_id in db:
        del db[user_id]
        db_write(db)
        # regenerate 3proxy managed block
        regenerate_all_users_to_3proxy()
    return RedirectResponse(url='/users', status_code=HTTP_303_SEE_OTHER)

@app.get('/user/{user_id}/speedtest', response_class=HTMLResponse)
async def user_speedtest_page(user_id: str, request: Request):
    """Speedtest page that shows live progress"""
    try:
        require_login(request)
    except HTTPException:
        return RedirectResponse(url='/login')
    db = db_read()
    if user_id not in db:
        raise HTTPException(status_code=404, detail='User not found')
    entry = db[user_id]
    return templates.TemplateResponse('speedtest.html', {
        'request': request,
        'user': entry,
        'user_id': user_id
    })

@app.post('/user/{user_id}/speedtest/start')
async def user_speedtest_start(user_id: str, request: Request):
    """Start speedtest in background"""
    try:
        require_login(request)
    except HTTPException:
        raise HTTPException(status_code=401, detail='Not authenticated')
    db = db_read()
    if user_id not in db:
        raise HTTPException(status_code=404, detail='User not found')
    
    # Initialize result
    SPEEDTEST_RESULTS[user_id] = {
        'status': 'running',
        'message': 'Initializing speedtest...',
        'download': 0,
        'upload': 0,
        'ping': 0,
        'progress': 0
    }
    
    # Start speedtest in background thread
    def run_speedtest():
        try:
            # Check if speedtest-cli is available
            try:
                subprocess.run(["speedtest-cli", "--version"], 
                             capture_output=True, check=True, timeout=5)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                SPEEDTEST_RESULTS[user_id] = {
                    'status': 'error',
                    'message': 'speedtest-cli is not installed. Install it with: pip install speedtest-cli',
                    'download': 0,
                    'upload': 0,
                    'ping': 0,
                    'progress': 0
                }
                return
            
            SPEEDTEST_RESULTS[user_id]['message'] = 'Finding best server...'
            SPEEDTEST_RESULTS[user_id]['progress'] = 10
            
            # Run speedtest with JSON output
            # Try with --secure first, fallback to without if it fails
            try:
                p = subprocess.Popen(
                    ["speedtest-cli", "--json", "--secure"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            except:
                p = subprocess.Popen(
                    ["speedtest-cli", "--json"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            
            SPEEDTEST_RESULTS[user_id]['message'] = 'Testing download speed...'
            SPEEDTEST_RESULTS[user_id]['progress'] = 40
            
            SPEEDTEST_RESULTS[user_id]['message'] = 'Testing upload speed...'
            SPEEDTEST_RESULTS[user_id]['progress'] = 70
            
            stdout, stderr = p.communicate(timeout=300)
            
            if p.returncode == 0:
                try:
                    res = json.loads(stdout)
                    download_mbps = res.get('download', 0) / 1e6
                    upload_mbps = res.get('upload', 0) / 1e6
                    ping_ms = res.get('ping', 0)
                    
                    SPEEDTEST_RESULTS[user_id] = {
                        'status': 'completed',
                        'message': 'Speedtest completed successfully!',
                        'download': round(download_mbps, 2),
                        'upload': round(upload_mbps, 2),
                        'ping': round(ping_ms, 2),
                        'progress': 100,
                        'server': res.get('server', {}).get('name', 'Unknown'),
                        'sponsor': res.get('server', {}).get('sponsor', 'Unknown')
                    }
                except json.JSONDecodeError:
                    SPEEDTEST_RESULTS[user_id] = {
                        'status': 'error',
                        'message': 'Failed to parse speedtest results',
                        'download': 0,
                        'upload': 0,
                        'ping': 0,
                        'progress': 0
                    }
                
                # Save to database
                db = db_read()
                if user_id in db:
                    db[user_id]['last_speed'] = round(download_mbps, 2)
                    db[user_id]['last_upload'] = round(upload_mbps, 2)
                    db[user_id]['last_ping'] = round(ping_ms, 2)
                    db_write(db)
            else:
                SPEEDTEST_RESULTS[user_id] = {
                    'status': 'error',
                    'message': f'Speedtest failed: {stderr[:100]}',
                    'download': 0,
                    'upload': 0,
                    'ping': 0,
                    'progress': 0
                }
        except subprocess.TimeoutExpired:
            p.kill()
            SPEEDTEST_RESULTS[user_id] = {
                'status': 'error',
                'message': 'Speedtest timed out',
                'download': 0,
                'upload': 0,
                'ping': 0,
                'progress': 0
            }
        except Exception as e:
            SPEEDTEST_RESULTS[user_id] = {
                'status': 'error',
                'message': f'Error: {str(e)}',
                'download': 0,
                'upload': 0,
                'ping': 0,
                'progress': 0
            }
    
    thread = threading.Thread(target=run_speedtest)
    thread.daemon = True
    thread.start()
    
    return JSONResponse({"status": "started", "message": "Speedtest started"})

@app.get('/user/{user_id}/speedtest/status')
async def user_speedtest_status(user_id: str, request: Request):
    """Get current speedtest status"""
    try:
        require_login(request)
    except HTTPException:
        raise HTTPException(status_code=401, detail='Not authenticated')
    
    if user_id not in SPEEDTEST_RESULTS:
        return JSONResponse({"status": "not_started", "message": "Speedtest not started"})
    
    return JSONResponse(SPEEDTEST_RESULTS.get(user_id, {"status": "unknown"}))

# ---------- 3proxy helpers ----------

def add_user_to_3proxy(entry, replace=False):
    """Add or update a single user in the managed block. If replace=True, regenerate from DB."""
    if replace:
        regenerate_all_users_to_3proxy()
        return
    # Always regenerate all users to ensure consistency
    regenerate_all_users_to_3proxy()


def regenerate_all_users_to_3proxy():
    db = db_read()
    lines = []
    for uid, e in db.items():
        lines.append(f"users {e['username']}:CL:{e['password']}")
        # if limits provided, add bandlim lines just before proxy
        # 3proxy bandlim uses bytes per second
        # 1 Mbps = 1,000,000 bits/sec = 125,000 bytes/sec
        if e.get('dl_limit',0)>0:
            bytes_per_sec = int(e['dl_limit'] * 125000)
            lines.append(f"bandlimout {bytes_per_sec}")
        if e.get('ul_limit',0)>0:
            bytes_per_sec = int(e['ul_limit'] * 125000)
            lines.append(f"bandlimin {bytes_per_sec}")
        lines.append(f"allow {e['username']}")
        
            # Add proxy types based on user selection
        proxy_type = e.get('proxy_type', 'both')
        if proxy_type in ['http', 'both']:
            lines.append(f"proxy -p{e['port']} -a")
        if proxy_type in ['socks5', 'both']:
            # SOCKS5 on same port or port+1 for 'both' (let's use port+1 to avoid conflicts)
            if proxy_type == 'both':
                socks_port = e['port'] + 1
            else:
                socks_port = e['port']
            lines.append(f"socks -p{socks_port} -a")
        
        lines.append("")
    write_managed(lines)
    restart_3proxy()

# ---------- START ----------
if __name__ == '__main__':
    import uvicorn
    print(f"Starting Proxy Panel on http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)
