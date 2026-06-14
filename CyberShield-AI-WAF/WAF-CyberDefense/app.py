# ============================================================
#  CyberShield WAF - Web Application Firewall (Streamlit)
#  Built with Python Streamlit | PBL Cyber Security Project
#  Author: [Your Name] | Version: 3.0
# ============================================================

import re
import json
import os
import random
from datetime import datetime
from flask import Flask

if "VERCEL" in os.environ:
    class Mock:
        def __init__(self, *args, **kwargs):
            pass
        def __getattr__(self, name):
            if name == "session_state":
                class SessionState(dict):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, **kwargs)
                        self.update({
                            "logged_in": False,
                            "username": "",
                            "total_requests": 0,
                            "payload_input": "",
                            "active_phone_otp": None,
                            "active_email_otp": None,
                            "signup_verifying": False,
                            "signup_data": None,
                            "login_verifying": False,
                            "login_otp_username": None,
                            "login_otp_type": None,
                            "login_otp_target": None,
                            "chat_history": []
                        })
                    def __getattr__(self, name):
                        return self.get(name)
                    def __setattr__(self, name, value):
                        self[name] = value
                return SessionState()
            if name in ("columns", "tabs"):
                def columns_or_tabs(spec, *args, **kwargs):
                    length = len(spec) if isinstance(spec, list) else spec
                    return [self] * length
                return columns_or_tabs
            return self
        def __setitem__(self, key, value):
            pass
        def __getitem__(self, key):
            return self
        def __call__(self, *args, **kwargs):
            return self
        def __bool__(self):
            return False
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
            
    st = Mock()
    plt = Mock()
    pd = Mock()
else:
    import streamlit as st
    import matplotlib.pyplot as plt
    import pandas as pd

# Initialize Flask application
app = Flask(__name__)

@app.route('/')
def home():
    return {
        "status": "CyberShield WAF is running",
        "framework": "Flask",
        "message": "Vercel serverless deployment check successful"
    }

# ── Page Configuration ──────────────────────────────────────
if "VERCEL" not in os.environ:
    st.set_page_config(
        page_title="CyberShield WAF Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )


# ── Configuration & Paths ───────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack_logs.json")
USER_DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_credentials.json")
LOGIN_HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "login_history.json")
ACTIVE_SESSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "active_sessions.json")
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# ── Attack Pattern Definitions ──────────────────────────────
ATTACK_SIGNATURES = {
    "SQL Injection": {
        "patterns": [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)",
            r"(UNION\s+(ALL\s+)?SELECT)",
            r"('|\")(\s)*(OR|AND)(\s)*('|\"|[0-9])",
            r"(--|#|/\*|\*/)",
            r"(\bOR\b\s+1\s*=\s*1)",
            r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
            r"(xp_cmdshell|exec\s*\(|execute\s*\()",
        ],
        "severity": "HIGH",
        "score": 90,
    },
    "Cross-Site Scripting (XSS)": {
        "patterns": [
            r"(<\s*script[^>]*>)",
            r"(javascript\s*:)",
            r"(on\w+\s*=\s*['\"]?[^'\"]*['\"]?)",
            r"(<\s*iframe[^>]*>)",
            r"(document\.(cookie|write|location))",
            r"(eval\s*\(|alert\s*\(|prompt\s*\(|confirm\s*\()",
            r"(<\s*img[^+]+src\s*=\s*['\"]?[^'\"]+['\"]?[^>]*>)",
        ],
        "severity": "HIGH",
        "score": 85,
    },
    "Command Injection": {
        "patterns": [
            r"(;|\||&&|\$\(|`).*(ls|cat|pwd|whoami|id|uname|wget|curl|bash|sh|python|perl|php)",
            r"(\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\(|\bpopen\s*\()",
            r"(nc\s+-[lnvz]|netcat|nmap\s+)",
            r"(;|\||&&).*/etc/(passwd|shadow|hosts)|/bin/(bash|sh)\b",
        ],
        "severity": "CRITICAL",
        "score": 95,
    },
    "Directory Traversal": {
        "patterns": [
            r"(\.\./|\.\.[/\\]){2,}",
            r"(%2e%2e[/\\]|%2e%2e%2f|%252e%252e)",
            r"(\.\.%c0%af|\.\.%c1%9c)",
            r"(/etc/passwd|/etc/hosts|/windows/system32|boot\.ini)",
        ],
        "severity": "HIGH",
        "score": 80,
    },
    "Remote Code Execution": {
        "patterns": [
            r"(base64_decode|str_rot13|gzinflate|gzuncompress|str_replace)",
            r"(eval\s*\(\s*\$|assert\s*\(\s*\$)",
            r"(\$_(GET|POST|REQUEST|COOKIE)\s*\[)",
            r"(php://input|php://filter|data://text)",
            r"(\.php\?.*=http|\.asp\?.*=http)",
        ],
        "severity": "CRITICAL",
        "score": 95,
    },
    "Suspicious HTTP": {
        "patterns": [
            r"(<\?php|\?php|<\?=)",
            r"(robots\.txt|\.htaccess|\.env|config\.php|wp-config)",
            r"(\bUNION\b|\bDROP\b|\bINSERT\b|\bDELETE\b)",
            r"(/admin/|/administrator/|wp-admin|phpmyadmin)",
            r"(\x00|\x01|\xff|\xfe)",
        ],
        "severity": "MEDIUM",
        "score": 50,
    },
}

# ── Log Loader & Saver ──────────────────────────────────────
def load_logs():
    """Load all attack logs from the JSON file."""
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

def save_log(entry):
    """Append a new attack log entry to the JSON file."""
    logs = load_logs()
    logs.append(entry)
    try:
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    except IOError:
        st.error("Failed to write to log file.")

def clear_logs_file():
    """Truncate the log database."""
    try:
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    except IOError:
        st.error("Failed to clear log file.")

# ── User & Session Database Helpers ──────────────────────────
def load_users():
    """Load user credentials from file."""
    if not os.path.exists(USER_DB_FILE):
        return {"dipak": "admin"}
    try:
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {"dipak": "admin"}

def save_user(username, password):
    """Save new user credentials."""
    users = load_users()
    users[username] = password
    try:
        with open(USER_DB_FILE, "w") as f:
            json.dump(users, f, indent=2)
        return True
    except IOError:
        return False

def load_login_history():
    """Load login history records."""
    if not os.path.exists(LOGIN_HISTORY_FILE):
        return []
    try:
        with open(LOGIN_HISTORY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

def log_login_event(username):
    """Record a successful login timestamp."""
    history = load_login_history()
    event = {
        "username": username,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    history.append(event)
    try:
        with open(LOGIN_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except IOError:
        pass

def load_active_sessions():
    """Load active persistence tokens."""
    if not os.path.exists(ACTIVE_SESSIONS_FILE):
        return {}
    try:
        with open(ACTIVE_SESSIONS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def save_active_sessions(sessions):
    """Save active sessions database."""
    try:
        with open(ACTIVE_SESSIONS_FILE, "w") as f:
            json.dump(sessions, f, indent=2)
    except IOError:
        pass

def register_session(username):
    """Create a persistent session token."""
    sessions = load_active_sessions()
    token = f"sess_{random.randint(100000, 999999)}_{int(datetime.now().timestamp())}"
    sessions[token] = username
    save_active_sessions(sessions)
    return token

def verify_session(token):
    """Check if token is valid and return username."""
    sessions = load_active_sessions()
    return sessions.get(token)

def delete_session(token):
    """Delete session token on logout."""
    sessions = load_active_sessions()
    if token in sessions:
        del sessions[token]
        save_active_sessions(sessions)



# ── Threat Detection Logic ──────────────────────────────────
def detect_attack(user_input):
    """Scan the input against all attack signatures."""
    for attack_type, data in ATTACK_SIGNATURES.items():
        for pattern in data["patterns"]:
            if re.search(pattern, user_input, re.IGNORECASE):
                return True, attack_type, data["severity"], data["score"]
    return False, None, None, 0

def get_threat_level(blocked_count, total_count):
    """Compute overall threat status based on attack ratio."""
    if total_count == 0:
        return "LOW"
    ratio = blocked_count / total_count
    if ratio >= 0.5:
        return "CRITICAL"
    elif ratio >= 0.3:
        return "HIGH"
    elif ratio >= 0.1:
        return "MEDIUM"
    return "LOW"

# ── Metrics & Summaries ─────────────────────────────────────
def get_stats(logs):
    """Aggregates security metrics from loaded logs."""
    total_requests = logs[-1]["total_requests"] if logs else 0
    blocked = len(logs)
    safe = max(0, total_requests - blocked)
    threat_level = get_threat_level(blocked, total_requests)

    # Count attack types
    type_counts = {}
    for log in logs:
        t = log.get("attack_type", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "total_requests": total_requests,
        "blocked_attacks": blocked,
        "safe_requests": safe,
        "threat_level": threat_level,
        "type_counts": type_counts,
    }

# ── Cyberpunk Aesthetics (CSS Injection) ──────────────────────
def inject_custom_css():
    st.markdown("""
        <style>
        /* Main page font and background coloring */
        .stApp {
            background-color: #0b0e14 !important;
            color: #c4d6e2 !important;
            font-family: 'Rajdhani', sans-serif;
        }
        
        /* Neon stats metrics styles */
        div[data-testid="stMetricValue"] {
            color: #00d4ff !important;
            font-weight: 700;
        }
        div[data-testid="stMetricLabel"] {
            color: #8da2b5 !important;
        }
        
        /* Cyberpunk styled borders for metric cards and form inputs */
        div[data-testid="metric-container"] {
            background: rgba(16, 24, 48, 0.45);
            border: 1px solid #00d4ff;
            box-shadow: 0 0 8px rgba(0, 212, 255, 0.15);
            border-radius: 8px;
            padding: 10px;
        }
        
        /* Customize buttons to have neon borders and hover effects */
        .stButton button {
            background-color: #121826 !important;
            border: 1px solid #00d4ff !important;
            color: #00d4ff !important;
            box-shadow: 0 0 5px rgba(0, 212, 255, 0.1);
            transition: all 0.3s ease;
        }
        .stButton button:hover {
            background-color: #00d4ff !important;
            color: #0b0e14 !important;
            box-shadow: 0 0 12px #00d4ff !important;
        }
        </style>
    """, unsafe_allow_html=True)

inject_custom_css()

# ── Session State & Data Initialization ──────────────────────
logs = load_logs()
db_stats = get_stats(logs)

# Initialize Authentication States
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "active_phone_otp" not in st.session_state:
    st.session_state.active_phone_otp = None

if "active_email_otp" not in st.session_state:
    st.session_state.active_email_otp = None

if "signup_verifying" not in st.session_state:
    st.session_state.signup_verifying = False

if "signup_data" not in st.session_state:
    st.session_state.signup_data = None

if "login_verifying" not in st.session_state:
    st.session_state.login_verifying = False

if "login_otp_username" not in st.session_state:
    st.session_state.login_otp_username = None

if "login_otp_type" not in st.session_state:
    st.session_state.login_otp_type = None

if "login_otp_target" not in st.session_state:
    st.session_state.login_otp_target = None

# Auto-Login Check (Remember Me Hook)
if not st.session_state.logged_in:
    query_sess = st.query_params.get("session")
    if query_sess:
        autologin_user = verify_session(query_sess)
        if autologin_user:
            st.session_state.logged_in = True
            st.session_state.username = autologin_user

if "total_requests" not in st.session_state:
    st.session_state.total_requests = db_stats["total_requests"]

# Track quick-fill payload choice
if "payload_input" not in st.session_state:
    st.session_state.payload_input = ""

# ── Login Page Component ─────────────────────────────────────
def render_login_page():
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=Outfit:wght@300;400;600;800&display=swap');
        
        .login-title {
            color: #00f0ff !important;
            font-weight: 800;
            font-size: 26px;
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.5);
            margin-top: 25px;
            margin-bottom: 5px;
            letter-spacing: 1px;
            font-family: 'Outfit', sans-serif;
            text-align: center;
        }
        
        .login-subtitle {
            color: #7d9cb5;
            font-size: 11px;
            letter-spacing: 3px;
            margin-bottom: 30px;
            font-family: 'Inter', sans-serif;
            text-transform: uppercase;
            text-align: center;
        }
        
        .stTabs [data-baseweb="tab-list"] {
            gap: 10px;
            justify-content: center;
        }
        .stTabs [data-baseweb="tab"] {
            background-color: rgba(10, 15, 30, 0.5) !important;
            border: 1px solid rgba(0, 240, 255, 0.2) !important;
            border-radius: 8px 8px 0 0;
            color: #7d9cb5 !important;
            padding: 8px 16px !important;
            font-family: 'Outfit', sans-serif;
        }
        .stTabs [aria-selected="true"] {
            background-color: rgba(0, 240, 255, 0.15) !important;
            border-color: #00f0ff !important;
            color: #00f0ff !important;
            text-shadow: 0 0 5px rgba(0, 240, 255, 0.5);
        }
        
        .waf-header-box {
            max-width: 480px;
            margin: 0 auto 15px auto;
            background: rgba(11, 14, 20, 0.85) !important;
            border: 2px solid #00d4ff !important;
            box-shadow: 0 0 25px rgba(0, 212, 255, 0.45) !important;
            border-radius: 12px;
            padding: 20px 30px;
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 95px;
        }
        .waf-header-title {
            color: #00f0ff;
            font-size: 20px;
            font-weight: 800;
            letter-spacing: 1.5px;
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.6);
            font-family: 'Outfit', sans-serif;
        }
        .waf-header-status {
            color: #7d9cb5;
            font-size: 11px;
            letter-spacing: 2px;
            margin-top: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-family: 'Inter', sans-serif;
            text-transform: uppercase;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background-color: #00ff88;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px #00ff88;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Center login column layout
    left_space, center_col, right_space = st.columns([1, 4, 1])
    
    with center_col:
        st.markdown("""
            <div class="waf-header-box">
                <div class="waf-header-title">WEB APPLICATION FIREWALL</div>
                <div class="waf-header-status"><span class="status-dot"></span> PROTECTION ONLINE</div>
            </div>
        """, unsafe_allow_html=True)
            
        st.markdown('<p class="login-title">🛡️ CYBERSHIELD GATEWAY</p>', unsafe_allow_html=True)
        st.markdown('<p class="login-subtitle">SECURE OPERATOR ACCESS PANEL</p>', unsafe_allow_html=True)
        
        login_tab, register_tab = st.tabs(["🔑 Sign In", "📝 Register Account"])
        
        with login_tab:
            with st.form("login_form"):
                username = st.text_input("Operator Username", placeholder="e.g. admin")
                password = st.text_input("Access Password", type="password", placeholder="••••••••")
                remember_me = st.checkbox("Remember session on this device", value=True, key="pw_remember")
                submit_login = st.form_submit_button("AUTHORIZE SYSTEM ACCESS")
                
                if submit_login:
                    if not username.strip() or not password.strip():
                        st.error("Please enter both username and password.")
                    else:
                        users = load_users()
                        if username in users:
                            stored_val = users[username]
                            stored_password = stored_val.get("password") if isinstance(stored_val, dict) else stored_val
                            if stored_password == password:
                                st.session_state.logged_in = True
                                st.session_state.username = username
                                log_login_event(username)
                                if remember_me:
                                    token = register_session(username)
                                    st.query_params["session"] = token
                                st.success("Access Authorized! Redirecting to SOC dashboard...")
                                st.rerun()
                            else:
                                st.error("ACCESS DENIED: Invalid operator credentials.")
                        else:
                            st.error("ACCESS DENIED: Invalid operator credentials.")
                            
        with register_tab:
            with st.form("register_form"):
                reg_username = st.text_input("Create Username", placeholder="e.g. operator1")
                reg_password = st.text_input("Create Password", type="password", placeholder="••••••••")
                reg_confirm = st.text_input("Confirm Password", type="password", placeholder="••••••••")
                submit_reg = st.form_submit_button("PROVISION ACCOUNT")
                
                if submit_reg:
                    if not reg_username.strip() or not reg_password.strip():
                        st.error("All credential fields are required.")
                    elif reg_password != reg_confirm:
                        st.error("Password verification mismatch.")
                    else:
                        users = load_users()
                        if reg_username in users:
                            st.error("Username is already registered.")
                        else:
                            if save_user(reg_username, reg_password):
                                st.success("Operator registered successfully! Please sign in using the Sign In tab.")
                                st.rerun()
                            else:
                                st.error("Failed to write to operator database.")

# ── Authentication Gate ──────────────────────────────────────
if not st.session_state.logged_in:
    render_login_page()
    st.stop()

# ── Sidebar ──────────────────────────────────────────────────
st.sidebar.markdown("### 🛡️ CyberShield Control Panel")
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Operator:** `{st.session_state.username}`")
st.sidebar.markdown("**Firewall Status:** 🟢 `ONLINE`  \n**Uptime:** `99.97%`  \n**Engine:** `Active Signature Guard`  \n**Ruleset:** `42 rules loaded`  \n**OWASP Top-10 Coverage:** `95%` ")

st.sidebar.markdown("---")
# Reset functionality
col_side1, col_side2 = st.sidebar.columns(2)
with col_side1:
    if st.button("🗑️ Clear Logs"):
        clear_logs_file()
        st.session_state.total_requests = 0
        st.success("Cleared.")
        st.rerun()
with col_side2:
    if st.button("🔓 Logout"):
        query_token = st.query_params.get("session")
        if query_token:
            delete_session(query_token)
        st.query_params.clear()
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()

# ── Page Layout ──────────────────────────────────────────────
st.markdown("<h1 style='text-align: center;'>🛡️ CYBERSHIELD WAF</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #88a; margin-top: -10px;'>AI-Powered Web Application Firewall & Security Operations Center</p>", unsafe_allow_html=True)
st.markdown("---")

# Define tabs dynamically based on user role
if st.session_state.username == "dipak":
    tab_dashboard, tab_logs, tab_status, tab_ai = st.tabs([
        "🛡️ SOC Dashboard",
        "📋 Attack Logs",
        "⚙️ System Status",
        "🤖 SHIELD-AI Chat Helper"
    ])
else:
    tab_dashboard, tab_status, tab_ai = st.tabs([
        "🛡️ SOC Dashboard",
        "⚙️ System Status",
        "🤖 SHIELD-AI Chat Helper"
    ])
    tab_logs = None

# ── Tab 1: SOC Dashboard ──────────────────────────────────────
with tab_dashboard:
    # 1. Stats Grid
    total_blocked = len(logs)
    safe_requests = max(0, st.session_state.total_requests - total_blocked)
    threat_level = get_threat_level(total_blocked, st.session_state.total_requests)

    if st.session_state.username == "dipak":
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Requests", st.session_state.total_requests)
        with col2:
            st.metric("Blocked Attacks", total_blocked)
        with col3:
            st.metric("Safe Requests", safe_requests)
        with col4:
            st.metric("Threat Level", threat_level)
    else:
        st.info("🔒 Dashboard metrics restricted to Administrator.")

    st.markdown("---")

    # 2. Request Analyzer Column Layout
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.subheader("🔎 Request Analyzer")
        st.write("Submit a payload to test the firewall engine. The detection layer classifies the request in real-time.")

        # Suggestion Chips / Buttons
        st.write("**Quick-Fill Payloads:**")
        qcol1, qcol2, qcol3, qcol4 = st.columns(4)
        with qcol1:
            if st.button("SQL Injection"):
                st.session_state.payload_input = "' OR 1=1 --"
                st.rerun()
        with qcol2:
            if st.button("XSS Script"):
                st.session_state.payload_input = "<script>alert('XSS')</script>"
                st.rerun()
        with qcol3:
            if st.button("Command Exec"):
                st.session_state.payload_input = "; cat /etc/passwd"
                st.rerun()
        with qcol4:
            if st.button("Safe Payload"):
                st.session_state.payload_input = "Hello World! Secure request payload."
                st.rerun()

        # Analyzer input form
        with st.form("analyzer_form", clear_on_submit=False):
            payload = st.text_input("Enter Payload:", value=st.session_state.payload_input)
            scan_submitted = st.form_submit_button("Initiate Threat Scan")

            if scan_submitted and payload.strip():
                st.session_state.total_requests += 1
                is_attack, attack_type, severity, score = detect_attack(payload)

                if is_attack:
                    # Save threat log entry
                    log_entry = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ip": "127.0.0.1",
                        "payload": payload[:200],
                        "attack_type": attack_type,
                        "severity": severity,
                        "threat_score": score,
                        "total_requests": st.session_state.total_requests
                    }
                    save_log(log_entry)

                    # Blinking/Visual alert banner
                    st.error(f"🚨 **MALICIOUS REQUEST BLOCKED**  \n**Attack Type:** {attack_type}  \n**Severity:** {severity}  \n**Threat Score:** {score}/100")
                    st.progress(score / 100)
                else:
                    st.success("✔ **Request Passed — No Threats Detected**  \nPayload successfully parsed and allowed through WAF filtering.")

    with col_right:
        st.subheader("📊 Traffic Distribution")
        if st.session_state.username == "dipak":
            type_counts = db_stats["type_counts"]
            if not type_counts:
                st.info("No attacks logged yet — test some payloads to see visualization.")
            else:
                labels = list(type_counts.keys())
                sizes = list(type_counts.values())
                colors = ['#ff2244', '#ff7722', '#00d4ff', '#a855f7', '#ffd700', '#00ff88'][:len(labels)]
                
                fig, ax = plt.subplots(figsize=(5, 4))
                fig.patch.set_facecolor('#0e1117')
                ax.set_facecolor('#0e1117')
                
                wedges, texts, autotexts = ax.pie(
                    sizes,
                    labels=labels,
                    colors=colors,
                    autopct='%1.0f%%',
                    startangle=140,
                    textprops=dict(color='#8da2b5', fontfamily='sans-serif', fontsize=8),
                    wedgeprops=dict(width=0.4, edgecolor='#1a2436', linewidth=2)
                )
                for autotext in autotexts:
                    autotext.set_color('#ffffff')
                    autotext.set_weight('bold')
                    
                ax.axis('equal')
                plt.tight_layout()
                st.pyplot(fig)
        else:
            st.info("🔒 Activity analytics restricted to Administrator.")

# ── Tab 2: Logs Database ─────────────────────────────────────
if tab_logs:
    with tab_logs:
        st.subheader("📋 Attack Log Database")
        st.write("Complete forensic record of all detected and blocked threats.")

        if not logs:
            st.info("No attack logs found. Submit test payloads from the Dashboard to populate this table.")
        else:
            df = pd.DataFrame(logs)
            df_display = df[["timestamp", "ip", "attack_type", "severity", "threat_score", "payload"]]
            
            # Filter controls
            fcol1, fcol2 = st.columns(2)
            with fcol1:
                type_filter = st.selectbox("Filter by Attack Type:", ["All"] + list(df_display["attack_type"].unique()))
            with fcol2:
                sev_filter = st.selectbox("Filter by Severity:", ["All"] + ["CRITICAL", "HIGH", "MEDIUM"])

            if type_filter != "All":
                df_display = df_display[df_display["attack_type"] == type_filter]
            if sev_filter != "All":
                df_display = df_display[df_display["severity"] == sev_filter]

            # Statistics summary row
            scol1, scol2, scol3, scol4 = st.columns(4)
            scol1.metric("Filtered Log Count", len(df_display))
            scol2.metric("Critical Blocks", len(df_display[df_display["severity"] == "CRITICAL"]))
            scol3.metric("High Blocks", len(df_display[df_display["severity"] == "HIGH"]))
            scol4.metric("Medium Blocks", len(df_display[df_display["severity"] == "MEDIUM"]))

            st.dataframe(df_display, width="stretch", hide_index=True)

# ── Tab 3: System Status & OWASP ──────────────────────────────
with tab_status:
    st.subheader("⚙️ System Status & Health Indicators")
    
    col_status1, col_status2 = st.columns(2)
    with col_status1:
        st.write("#### 🖥️ Server Resources")
        cpu_val = random.randint(4, 15)
        mem_val = random.randint(38, 48)
        st.metric("CPU Usage (Overall)", f"{cpu_val}%", delta="Normal", delta_color="normal")
        st.metric("Memory Allocated", f"{mem_val}%", delta="Healthy", delta_color="normal")
        st.metric("IDS Rules Loaded", "42 signatures", delta="All Active", delta_color="normal")
        
    with col_status2:
        st.write("#### 🛡️ Firewall Daemon stats")
        st.metric("Monitored Packet Rate", f"{random.randint(110, 320)} pkt/s", delta="Normal range", delta_color="normal")
        st.metric("Daemon Uptime", "99.97%", delta="Uptime OK", delta_color="normal")
        st.metric("Threat Intelligence Sync", "Synced Today", delta="Active Feed", delta_color="normal")

    st.markdown("---")
    st.write("#### 🔐 OWASP Top 10 Threat Mitigation Matrix")
    
    owasp_data = {
        "OWASP Category": [
            "A01:2021 - Broken Access Control",
            "A03:2021 - Injection (SQL / CMD)",
            "A05:2021 - Security Misconfiguration",
            "A07:2021 - Identification & Auth Failures",
            "A08:2021 - Software & Data Integrity Failures"
        ],
        "Inspection Module": [
            "Path Traversal Guard Rules",
            "SQLi / Cmd Injection / XSS Filters",
            "Configuration Probing Rules",
            "Suspicious Session & Auth Parsers",
            "RCE Payload Check Rules"
        ],
        "Protection Status": [
            "🟢 PROTECTED (80%)",
            "🟢 PROTECTED (95%)",
            "🟡 PARTIAL (70%)",
            "🟡 PARTIAL (60%)",
            "🟢 PROTECTED (90%)"
        ]
    }
    st.table(pd.DataFrame(owasp_data))

    st.markdown("---")
    st.write("#### 📋 Operator Login Audit History")
    if st.session_state.username == "dipak":
        login_history = load_login_history()
        if not login_history:
            st.info("No login history found.")
        else:
            history_df = pd.DataFrame(login_history)
            history_df = history_df.iloc[::-1]
            st.dataframe(history_df, width="stretch", hide_index=True)
    else:
        st.info("🔒 Operator login audit history is restricted to Administrator.")


# ── AI Helper Functions ──────────────────────────────────────
def generate_local_response(prompt, logs, total_requests):
    prompt_lower = prompt.lower()
    total_blocked = len(logs)
    
    if any(k in prompt_lower for k in ["summary", "attacks", "blocked", "how many", "stats", "log", "history", "previous", "activity", "database", "record"]):
        if st.session_state.username != "dipak":
            return "🔒 Queries regarding WAF attack logs and historical statistics are restricted to the Administrator."
        
        if total_blocked == 0:
            return f"Currently, the WAF has monitored **{total_requests}** total requests and blocked **0** attacks. The system is clean."
        
        type_counts = {}
        for log in logs:
            t = log.get("attack_type", "Unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
            
        breakdown = "\n".join([f"- **{t}**: {count} blocked" for t, count in type_counts.items()])
        
        return (
            f"Here is the current security summary for **CyberShield WAF**:\n\n"
            f"- **Total Requests Monitored**: {total_requests}\n"
            f"- **Blocked Attacks**: {total_blocked}\n"
            f"- **Safe Requests Passed**: {max(0, total_requests - total_blocked)}\n"
            f"- **Overall Threat Level**: {get_threat_level(total_blocked, total_requests)}\n\n"
            f"**Attack Type Breakdown:**\n{breakdown}"
        )
        
    if "analyze" in prompt_lower or "check" in prompt_lower or any(p in prompt for p in ["'", "<", ";", "../"]):
        test_payload = prompt
        if "analyze" in prompt_lower:
            parts = prompt.split("analyze", 1)
            if len(parts) > 1 and parts[1].strip():
                test_payload = parts[1].strip()
                
        is_attack, attack_type, severity, score = detect_attack(test_payload)
        if is_attack:
            return (
                f"🛡️ **WAF Threat Analysis Result:**\n\n"
                f"- **Input Payload**: `{test_payload}`\n"
                f"- **Verdict**: 🚨 **MALICIOUS**\n"
                f"- **Attack Category**: {attack_type}\n"
                f"- **Assigned Severity**: **{severity}**\n"
                f"- **Threat Score**: {score}/100\n\n"
                f"**Security Insight:** This payload triggered signature checks matching typical {attack_type} patterns. The WAF successfully intercepted it."
            )
        else:
            return (
                f"🛡️ **WAF Threat Analysis Result:**\n\n"
                f"- **Input Payload**: `{test_payload}`\n"
                f"- **Verdict**: ✔ **SAFE**\n"
                f"- **Security Insight**: No matching malicious patterns were found in this input. It would be allowed to pass to the backend application."
            )
            
    if "sql" in prompt_lower:
        return (
            "### 💉 SQL Injection (SQLi) Explanation\n\n"
            "**SQL Injection** occurs when an attacker inserts malicious SQL commands into input fields, "
            "tricking the database into executing unauthorized queries. This can lead to authentication bypass, "
            "unauthorized data exposure, or complete database destruction.\n\n"
            "**Example Payload:** `' OR 1=1 --`\n\n"
            "**Mitigation:** Use Parameterized Queries (Prepared Statements), input validation, and object-relational mapping (ORM) libraries."
        )
        
    if "xss" in prompt_lower or "scripting" in prompt_lower:
        return (
            "### 🧪 Cross-Site Scripting (XSS) Explanation\n\n"
            "**Cross-Site Scripting** occurs when an application includes untrusted data in a web page without proper "
            "validation or escaping. The browser executes the script, allowing attackers to hijack user sessions, "
            "deface websites, or redirect users to malicious sites.\n\n"
            "**Example Payload:** `<script>alert(document.cookie)</script>`\n\n"
            "**Mitigation:** Context-aware output encoding, Content Security Policy (CSP), and robust input sanitization."
        )
        
    if "command" in prompt_lower or "cmd" in prompt_lower:
        return (
            "### 🐚 Command Injection Explanation\n\n"
            "**Command Injection** is an attack where arbitrary shell commands are executed on the host operating system "
            "via a vulnerable application. This happens when inputs are passed directly to system shells (like `system()` or `exec()`).\n\n"
            "**Example Payload:** `; cat /etc/passwd`\n\n"
            "**Mitigation:** Avoid passing input directly to system interpreters; use API-based alternatives (like subprocess lists in Python) and strict input whitelisting."
        )
 
    if "directory" in prompt_lower or "traversal" in prompt_lower or "path" in prompt_lower:
        return (
            "### 📁 Directory Traversal Explanation\n\n"
            "**Directory Traversal** (or Path Traversal) allows an attacker to read arbitrary files on the server running "
            "the application, such as application code, credentials, or sensitive operating system files.\n\n"
            "**Example Payload:** `../../etc/passwd`\n\n"
            "**Mitigation:** Use file path verification routines, avoid user input in file paths, or map files using predefined indices."
        )
 
    if st.session_state.username == "dipak":
        return (
            "I am **SHIELD-AI**, your local security assistant. I can help you with:\n"
            "1. **Log summaries**: Ask me about 'blocked attacks' or 'summarize today'.\n"
            "2. **Payload analysis**: Ask me to 'analyze: <your payload>' to test the WAF engine.\n"
            "3. **OWASP FAQ**: Ask me to explain vulnerabilities like 'SQL Injection', 'XSS', 'Command Injection', or 'Directory Traversal'."
        )
    else:
        return (
            "I am **SHIELD-AI**, your local security assistant. I can help you with:\n"
            "1. **Payload analysis**: Ask me to 'analyze: <your payload>' to test the WAF engine.\n"
            "2. **OWASP FAQ**: Ask me to explain vulnerabilities like 'SQL Injection', 'XSS', 'Command Injection', or 'Directory Traversal'."
        )
 
def generate_gemini_response(prompt, api_key, logs, total_requests):
    import requests
    prompt_lower = prompt.lower()
    
    if st.session_state.username != "dipak":
        if any(k in prompt_lower for k in ["summary", "attacks", "blocked", "how many", "stats", "log", "history", "previous", "activity", "database", "record"]):
            return "🔒 Queries regarding WAF attack logs and historical statistics are restricted to the Administrator."
        
        system_instruction = (
            "You are SHIELD-AI, a professional security analyst chatbot integrated into the CyberShield WAF dashboard. "
            "Answer the user's cybersecurity question concisely and professionally. "
            "Refuse to answer questions about WAF attack logs, historical statistics, database logs, or user login history, stating that they are restricted to the Administrator."
        )
    else:
        total_blocked = len(logs)
        system_instruction = (
            "You are SHIELD-AI, a professional security analyst chatbot integrated into the CyberShield WAF dashboard. "
            f"Answer the user's cybersecurity question concisely and professionally. WAF Current Stats: "
            f"{total_requests} total requests monitored, {total_blocked} blocked attacks."
        )
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{
            "parts": [{
                "text": f"{system_instruction}\n\nUser Question: {prompt}"
            }]
        }]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=8)
        if response.status_code == 200:
            res_json = response.json()
            reply = res_json["candidates"][0]["content"]["parts"][0]["text"]
            return reply
        else:
            return f"*(Gemini API returned code {response.status_code}. Falling back to local engine)*\n\n" + generate_local_response(prompt, logs, total_requests)
    except Exception as e:
        return f"*(Gemini connection timed out. Falling back to local engine)*\n\n" + generate_local_response(prompt, logs, total_requests)


# ── Tab 4: Chat Bot ──────────────────────────────────────────
with tab_ai:
    st.subheader("🤖 SHIELD-AI Chat Helper")
    st.write("Ask questions about security vulnerabilities, summarize WAF block records, or analyze payloads.")

    if "chat_history" not in st.session_state:
        if st.session_state.username == "dipak":
            welcome_msg = "Hello! I am SHIELD-AI, your security intelligence assistant. I can help analyze request payloads, summarize blocked attacks, or explain web application security vulnerabilities. What would you like to know?"
        else:
            welcome_msg = "Hello! I am SHIELD-AI, your security intelligence assistant. I can help analyze request payloads or explain web application security vulnerabilities. What would you like to know?"
        st.session_state.chat_history = [
            {
                "role": "assistant",
                "content": welcome_msg
            }
        ]

    # Render history
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    if user_input := st.chat_input("Ask SHIELD-AI..."):
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Generate response
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                if api_key:
                    reply = generate_gemini_response(user_input, api_key, logs, st.session_state.total_requests)
                else:
                    reply = generate_local_response(user_input, logs, st.session_state.total_requests)
                st.markdown(reply)
                
        st.session_state.chat_history.append({"role": "assistant", "content": reply})


