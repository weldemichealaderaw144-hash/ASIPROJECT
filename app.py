import json
import os
import subprocess
import threading
import tempfile
import logging
import re
import ipaddress
import shutil
import socket
import secrets
import string
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

import plotly
import plotly.graph_objs as go
from flask import (
    Flask, render_template, redirect, url_for, request, session,
    flash, abort, jsonify, has_request_context, current_app
)
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, desc
from sqlalchemy.exc import IntegrityError

# ------------------ Tool path resolution ------------------
GO_BIN = os.path.expanduser(r"~\go\bin")

def find_tool(name):
    """Locate a tool in environment PATH, GO_BIN, or a specific env var."""
    env_path = os.environ.get(name.upper() + "_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    path = shutil.which(name) or shutil.which(name + ".exe")
    if path:
        return path
    go_path = os.path.join(GO_BIN, name + (".exe" if os.name == "nt" else ""))
    if os.path.exists(go_path):
        return go_path
    return None

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///asi.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCHEDULER_API_ENABLED = True

    # Tool paths – will be None if not found
    SUBFINDER_PATH = find_tool("subfinder")
    HTTPX_PATH = find_tool("httpx")
    NUCLEI_PATH = find_tool("nuclei")
    AMASS_PATH = find_tool("amass")
    ASSETFINDER_PATH = find_tool("assetfinder")
    GOWITNESS_PATH = find_tool("gowitness")
    DNSX_PATH = find_tool("dnsx")
    WHATWEB_PATH = find_tool("whatweb")
    WAPPALYZER_PATH = find_tool("wappalyzer")
    KATANA_PATH = find_tool("katana")
    NAABU_PATH = find_tool("naabu")
    SUBZY_PATH = find_tool("subzy")
    GAU_PATH = find_tool("gau")
    THEHARVESTER_PATH = find_tool("theharvester")

    SCAN_SEMAPHORE_VALUE = int(os.environ.get("SCAN_SEMAPHORE", "3"))

# ================= INIT EXTENSIONS =================
db = SQLAlchemy()
scheduler = APScheduler()
scan_semaphore = threading.Semaphore(Config.SCAN_SEMAPHORE_VALUE)

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO if os.environ.get("FLASK_ENV") == "production" else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ================= MODELS =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(80), nullable=False)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    risk_score = db.Column(db.Integer, default=0, index=True)

    monitoring_enabled = db.Column(db.Boolean, default=True)
    monitoring_frequency = db.Column(db.String(20), default="daily")
    last_monitored_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans = db.relationship("Scan", backref="asset", lazy=True, cascade="all, delete-orphan")
    inventory = db.relationship("AssetInventory", backref="asset", lazy=True, cascade="all, delete-orphan")
    vulnerabilities = db.relationship("Vulnerability", backref="asset", lazy=True, cascade="all, delete-orphan")

    def update_risk_score(self):
        """Calculate risk score (0-100) based on approved assets and vulnerabilities."""
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

        vuln_results = db.session.query(
            Vulnerability.severity,
            func.count(Vulnerability.id)
        ).filter_by(asset_id=self.id).group_by(Vulnerability.severity).all()
        vuln_score = sum(severity_weights.get(sev.lower(), 0) * count for sev, count in vuln_results)

        services_count = AssetInventory.query.filter_by(
            parent_asset_id=self.id,
            asset_type='service',
            status='approved'
        ).count()
        service_score = min(services_count * 0.2, 10)

        tech_count = AssetInventory.query.filter_by(
            parent_asset_id=self.id,
            asset_type='technology',
            status='approved'
        ).count()
        tech_score = min(tech_count * 0.1, 5)

        port_count = AssetInventory.query.filter_by(
            parent_asset_id=self.id,
            asset_type='port',
            status='approved'
        ).count()
        port_score = min(port_count * 0.1, 5)

        total_score = vuln_score + service_score + tech_score + port_score
        self.risk_score = min(int(total_score), 100)
        return self.risk_score

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"))
    status = db.Column(db.String(50), default="running")
    subfinder_status = db.Column(db.String(50), default="pending")
    httpx_status = db.Column(db.String(50), default="pending")
    nuclei_status = db.Column(db.String(50), default="pending")
    amass_status = db.Column(db.String(50), default="pending")
    assetfinder_status = db.Column(db.String(50), default="pending")
    whatweb_status = db.Column(db.String(50), default="pending")
    gowitness_status = db.Column(db.String(50), default="pending")
    dnsx_status = db.Column(db.String(50), default="pending")
    wappalyzer_status = db.Column(db.String(50), default="pending")
    katana_status = db.Column(db.String(50), default="pending")
    naabu_status = db.Column(db.String(50), default="pending")
    subzy_status = db.Column(db.String(50), default="pending")
    gau_status = db.Column(db.String(50), default="pending")
    theharvester_status = db.Column(db.String(50), default="pending")

    error_message = db.Column(db.Text)
    finished_at = db.Column(db.DateTime)
    scan_type = db.Column(db.String(20), default="manual")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class AssetInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"), index=True)
    asset_type = db.Column(db.String(50), index=True)
    value = db.Column(db.String(500), nullable=False, index=True)
    version = db.Column(db.String(100), nullable=True)
    screenshot_path = db.Column(db.String(500), nullable=True)
    asset_metadata = db.Column(db.JSON)
    status = db.Column(db.String(50), default="approved", index=True)
    discovered_by = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint("parent_asset_id", "asset_type", "value", name="unique_asset_entry"),
    )

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    username = db.Column(db.String(80))
    role = db.Column(db.String(80))
    action = db.Column(db.String(100))
    target = db.Column(db.String(150))
    status = db.Column(db.String(50))
    severity = db.Column(db.String(50))
    ip = db.Column(db.String(50))
    details = db.Column(db.Text, nullable=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("asset.id"), index=True)
    url = db.Column(db.String(500), index=True)
    template_id = db.Column(db.String(200), index=True)
    severity = db.Column(db.String(50), index=True)
    name = db.Column(db.String(300))
    matched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    notes = db.Column(db.Text, nullable=True)  # For analysts to add notes/tags

# ================= HELPER FUNCTIONS =================
def normalize(value):
    return value.strip().lower() if value else ""

def is_valid_domain(domain):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$'
    return bool(re.match(pattern, domain)) and len(domain) <= 255

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_url(url):
    return url.startswith(('http://', 'https://')) and '.' in url

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def check_tool(path):
    if not path or not os.path.exists(path):
        raise RuntimeError(f"Tool not found or path not set: {path}")

def get_risk_level(score):
    if score >= 80:
        return "Extreme"
    if score >= 50:
        return "Severe"
    if score >= 20:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"

def log_activity(action, target, status="SUCCESS", severity="INFO", details=None, ip=None):
    if ip is None and has_request_context():
        ip = request.remote_addr
    username = session.get("username", "system") if has_request_context() else "system"
    role = session.get("role", "system") if has_request_context() else "system"
    activity = ActivityLog(
        username=username,
        role=role,
        action=action,
        target=target,
        status=status,
        severity=severity,
        ip=ip,
        details=details
    )
    db.session.add(activity)
    db.session.commit()

def handle_shadow(asset_id, value, asset_type, source, version=None, asset_metadata=None):
    value = normalize(value)
    if not value:
        return
    try:
        existing = AssetInventory.query.filter_by(
            parent_asset_id=asset_id,
            asset_type=asset_type,
            value=value
        ).first()
        if existing:
            if existing.status == "rejected":
                existing.status = "shadow"
                existing.discovered_by = source
                existing.created_at = datetime.now(timezone.utc)
                if version:
                    existing.version = version
                if asset_metadata:
                    existing.asset_metadata = asset_metadata
                db.session.commit()
                log_activity(
                    action="SHADOW_ASSET_REACTIVATED",
                    target=value,
                    severity="INFO",
                    details=f"{asset_type} rediscovered via {source}"
                )
            return
        shadow = AssetInventory(
            parent_asset_id=asset_id,
            asset_type=asset_type,
            value=value,
            version=version,
            asset_metadata=asset_metadata,
            status="shadow",
            discovered_by=source
        )
        db.session.add(shadow)
        db.session.commit()
        log_activity(
            action="SHADOW_ASSET_DETECTED",
            target=value,
            severity="WARNING",
            details=f"{asset_type} discovered via {source}"
        )
    except IntegrityError:
        db.session.rollback()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Shadow insert error: {e}")

def convert_ports_to_urls(ports):
    urls = []
    for ip, port in ports:
        if port in ("80", "8080"):
            urls.append(f"http://{ip}:{port}")
        elif port == "443":
            urls.append(f"https://{ip}")
        else:
            urls.append(f"http://{ip}:{port}")
    return urls

# ================= PASSWORD STRENGTH VALIDATOR =================
def is_strong_password(password):
    """Check password strength: min 8 chars, upper, lower, digit, special."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "Strong password."

# ================= DECORATORS =================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ================= SCAN FUNCTIONS =================
def run_subfinder(asset):
    found = []
    try:
        check_tool(Config.SUBFINDER_PATH)
        cmd = [Config.SUBFINDER_PATH, "-d", asset.domain, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in result.stdout.splitlines():
            sub = normalize(line)
            if sub and sub != asset.domain:
                found.append(sub)
                handle_shadow(asset.id, sub, "subdomain", "subfinder")
    except Exception as e:
        logger.error(f"Subfinder error: {e}")
    return found

def run_httpx(asset, subdomains):
    urls, ips = [], set()
    temp_path = None

    def normalize_target(t):
        if not t.startswith("http"):
            return "http://" + t
        return t

    targets = [normalize_target(t) for t in (subdomains or [asset.domain])]

    try:
        check_tool(Config.HTTPX_PATH)

        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as f:
            f.write("\n".join(targets))
            f.flush()
            temp_path = f.name

        cmd = [
            Config.HTTPX_PATH,
            "-l", temp_path,
            "-json",
            "-status-code",
            "-ip",
            "-threads", "30",
            "-timeout", "10",
            "-retries", "2",
            "-silent"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                url = data.get("url") or data.get("input")
                if not url:
                    continue

                status_code = str(data.get("status_code", ""))
                if not status_code.startswith(("2", "3")):
                    continue

                urls.append(url)
                handle_shadow(asset.id, url, "url", "httpx")

                ip = data.get("ip")
                if ip and ipaddress.ip_address(ip).version == 4:
                    if ip not in ips:
                        ips.add(ip)
                        handle_shadow(asset.id, ip, "ip", "httpx")

            except Exception:
                continue

        # Fallback IP resolution if none found
        if not ips:
            try:
                ip = socket.gethostbyname(asset.domain)
                logger.warning(f"[FIX] Fallback IP used: {ip}")
                ips.add(ip)
            except Exception as e:
                logger.error(f"DNS fallback failed: {e}")

        logger.info(f"[HTTPX] Found {len(urls)} URLs and {len(ips)} IPs")

    except Exception as e:
        logger.error(f"Httpx error: {e}")

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)

    return urls, list(ips)

def run_naabu(asset, ips):
    discovered = []
    if not Config.NAABU_PATH or not ips:
        return discovered
    valid_ips = [ip for ip in ips if is_valid_ip(ip)]
    if not valid_ips:
        return discovered
    temp_path = None
    try:
        check_tool(Config.NAABU_PATH)
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as f:
            f.write("\n".join(valid_ips))
            f.flush()
            temp_path = f.name
        cmd = [
            Config.NAABU_PATH, "-list", temp_path,
            "-top-ports", "1000", "-sV", "-json",
            "-rate", "1000", "-timeout", "5", "-silent"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                ip = data.get("ip")
                port = str(data.get("port"))
                if not ip or not is_valid_port(port):
                    continue
                discovered.append((ip, port))
                handle_shadow(asset.id, f"{ip}:{port}", "port", "naabu")
                service = data.get("service")
                if service:
                    version = data.get("version")
                    handle_shadow(asset.id, f"{service}:{port}", "service", "naabu", version=version)
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error(f"Naabu error: {e}")
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return discovered

def run_gau(asset):
    urls = []
    if not Config.GAU_PATH:
        return urls
    try:
        check_tool(Config.GAU_PATH)
        cmd = [Config.GAU_PATH, asset.domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in result.stdout.splitlines():
            url = line.strip()
            if url:
                urls.append(url)
                if "/api/" in url or "?api" in url or ".json" in url:
                    handle_shadow(asset.id, url, "api_endpoint", "gau")
                else:
                    handle_shadow(asset.id, url, "url", "gau")
    except Exception as e:
        logger.error(f"Gau error: {e}")
    return urls

def run_katana(asset, urls):
    discovered = []
    if not Config.KATANA_PATH or not urls:
        return discovered
    temp_path = None
    try:
        check_tool(Config.KATANA_PATH)
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as f:
            f.write("\n".join(urls))
            f.flush()
            temp_path = f.name
        cmd = [
            Config.KATANA_PATH, "-list", temp_path, "-json", "-depth", "2", "-jc",
            "-ct", "200,301,302", "-c", "50", "-delay", "1s", "-silent"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                endpoint = data.get("endpoint") or data.get("url")
                if not endpoint:
                    continue
                discovered.append(endpoint)
                asset_type = "api_endpoint" if any(x in endpoint for x in ["/api/", "?api", ".json", "/v1/", "/v2/", "/graphql"]) else "url"
                handle_shadow(asset.id, endpoint, asset_type, "katana")
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error(f"Katana error: {e}")
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return discovered

def run_dnsx(asset, subdomains):
    records = []
    if not Config.DNSX_PATH:
        return records
    targets = [asset.domain] + (subdomains if subdomains else [])
    try:
        check_tool(Config.DNSX_PATH)
        for target in targets:
            cmd = [Config.DNSX_PATH, "-d", target, "-a", "-aaaa", "-cname", "-ns", "-mx", "-txt", "-json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in result.stdout.splitlines():
                try:
                    data = json.loads(line)
                    record_type = data.get("type")
                    value = data.get("value")
                    if record_type and value:
                        handle_shadow(asset.id, value, f"dns_{record_type.lower()}", "dnsx")
                        records.append((record_type, value))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error(f"Dnsx error: {e}")
    return records

def run_whatweb(asset, urls):
    techs = []
    if not Config.WHATWEB_PATH or not urls:
        return techs
    try:
        check_tool(Config.WHATWEB_PATH)
        cmd = [Config.WHATWEB_PATH, "--log-json", "-", "--no-errors"] + urls[:50]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                plugins = data.get("plugins", {})
                for plugin_name, plugin_info in plugins.items():
                    version = None
                    if "version" in plugin_info and plugin_info["version"]:
                        version = plugin_info["version"][0] if isinstance(plugin_info["version"], list) else plugin_info["version"]
                    handle_shadow(asset.id, plugin_name, "technology", "whatweb", version=version)
                    techs.append(plugin_name)
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error(f"Whatweb error: {e}")
    return techs

def run_wappalyzer(asset, urls):
    techs = []
    if not Config.WAPPALYZER_PATH or not urls:
        return techs
    try:
        check_tool(Config.WAPPALYZER_PATH)
        for url in urls[:10]:
            cmd = [Config.WAPPALYZER_PATH, url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                continue
            try:
                data = json.loads(result.stdout)
                for tech_name, tech_info in data.get("technologies", {}).items():
                    version = tech_info.get("version")
                    handle_shadow(asset.id, tech_name, "technology", "wappalyzer", version=version)
                    techs.append(tech_name)
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error(f"Wappalyzer error: {e}")
    return techs

def run_subzy(asset, subdomains):
    findings = []
    if not Config.SUBZY_PATH or not subdomains:
        return findings
    temp_path = None
    try:
        check_tool(Config.SUBZY_PATH)
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as f:
            f.write("\n".join(subdomains))
            f.flush()
            temp_path = f.name
        cmd = [
            Config.SUBZY_PATH, "run", "--targets", temp_path,
            "--output", "json", "--hide_fails", "--concurrency", "20", "--timeout", "10"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        try:
            data = json.loads(result.stdout)
            for item in data:
                vulnerable_domain = item.get("domain")
                service = item.get("service")
                if not vulnerable_domain:
                    continue
                vuln = Vulnerability(
                    asset_id=asset.id,
                    url=vulnerable_domain,
                    template_id="subdomain-takeover",
                    severity="high",
                    name=f"Subdomain takeover: {service}" if service else "Subdomain takeover",
                    matched_at=datetime.now(timezone.utc)
                )
                db.session.add(vuln)
                findings.append(vulnerable_domain)
                handle_shadow(asset.id, vulnerable_domain, "subdomain", "subzy",
                              asset_metadata={"takeover": True, "service": service})
            if findings:
                db.session.commit()
        except json.JSONDecodeError:
            for line in result.stdout.splitlines():
                if "Vulnerable" in line or "TAKEOVER" in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith("http") or "." in part:
                            findings.append(part)
                            handle_shadow(asset.id, part, "subdomain", "subzy")
                            break
    except Exception as e:
        logger.error(f"Subzy error: {e}")
        db.session.rollback()
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return findings

def run_nuclei(asset, urls):
    if not urls:
        return []
    findings = []
    processed_urls = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            processed_urls.append(f"http://{url}")
            processed_urls.append(f"https://{url}")
        else:
            processed_urls.append(url)
    processed_urls = list(set(processed_urls))
    temp_path = None
    try:
        check_tool(Config.NUCLEI_PATH)
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as f:
            f.write("\n".join(processed_urls))
            f.flush()
            temp_path = f.name
        cmd = [
            Config.NUCLEI_PATH, "-l", temp_path,
            "-severity", "critical,high,medium,low,info",
            "-jsonl", "-silent", "-no-color", "-timeout", "10", "-retries", "2",
            "-rate-limit", "50", "-stats", "-irr"
        ]
        env = os.environ.copy()
        env['NUCLEI_HEADLESS'] = 'true'
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200, env=env)
        new_vulns = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                template_id = data.get("template-id") or data.get("template", "unknown")
                info = data.get("info", {})
                severity = info.get("severity", data.get("severity", "unknown"))
                name = info.get("name", data.get("name", "Unknown vulnerability"))
                matched_url = data.get("matched-at") or data.get("host") or data.get("url") or data.get("ip", "")
                if matched_url:
                    existing = Vulnerability.query.filter_by(
                        asset_id=asset.id,
                        url=matched_url[:500],
                        template_id=template_id[:200],
                        name=name[:300]
                    ).first()
                    if not existing:
                        vuln = Vulnerability(
                            asset_id=asset.id,
                            url=matched_url[:500],
                            template_id=template_id[:200],
                            severity=severity,
                            name=name[:300],
                            matched_at=datetime.now(timezone.utc)
                        )
                        new_vulns.append(vuln)
                findings.append(data)
            except Exception:
                continue
        if new_vulns:
            db.session.bulk_save_objects(new_vulns)
            db.session.commit()
            asset.update_risk_score()
            db.session.commit()
    except Exception as e:
        logger.error(f"Nuclei error: {e}")
        db.session.rollback()
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
    return findings

def run_gowitness(asset, urls):
    if not Config.GOWITNESS_PATH or not urls:
        return
    try:
        check_tool(Config.GOWITNESS_PATH)
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".txt") as f:
            f.write("\n".join(urls))
            f.flush()
            temp_path = f.name
        screenshot_dir = os.path.join("screenshots", str(asset.id))
        os.makedirs(screenshot_dir, exist_ok=True)
        cmd = [
            Config.GOWITNESS_PATH, "file", "-f", temp_path,
            "--destination", screenshot_dir, "--threads", "3"
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        os.unlink(temp_path)
    except Exception as e:
        logger.error(f"Gowitness error: {e}")

def run_theharvester(asset):
    emails = []
    if not Config.THEHARVESTER_PATH:
        return emails
    try:
        check_tool(Config.THEHARVESTER_PATH)
        cmd = [Config.THEHARVESTER_PATH, "-d", asset.domain, "-b", "all", "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        for line in result.stdout.splitlines():
            if "@" in line and "." in line.split("@")[1]:
                email = line.strip()
                if is_valid_email(email):
                    emails.append(email)
                    handle_shadow(asset.id, email, "email", "theHarvester")
    except Exception as e:
        logger.error(f"TheHarvester error: {e}")
    return emails

def run_amass(asset):
    found = []
    if not Config.AMASS_PATH:
        return found
    try:
        check_tool(Config.AMASS_PATH)
        cmd = [Config.AMASS_PATH, "enum", "-passive", "-d", asset.domain, "-o", "-"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        for line in result.stdout.splitlines():
            sub = normalize(line)
            if sub and sub != asset.domain:
                found.append(sub)
                handle_shadow(asset.id, sub, "subdomain", "amass")
    except Exception as e:
        logger.error(f"Amass error: {e}")
    return found

def run_assetfinder(asset):
    found = []
    if not Config.ASSETFINDER_PATH:
        return found
    try:
        check_tool(Config.ASSETFINDER_PATH)
        cmd = [Config.ASSETFINDER_PATH, "--subs-only", asset.domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in result.stdout.splitlines():
            sub = normalize(line)
            if sub and sub != asset.domain:
                found.append(sub)
                handle_shadow(asset.id, sub, "subdomain", "assetfinder")
    except Exception as e:
        logger.error(f"Assetfinder error: {e}")
    return found

def background_scan(app, asset_id, scan_type="manual"):
    with scan_semaphore:
        with app.app_context():
            asset = db.session.get(Asset, asset_id)
            if not asset:
                logger.error(f"Asset {asset_id} not found")
                return

            # Check for already running scan
            running = Scan.query.filter_by(asset_id=asset_id, status="running").first()
            if running:
                logger.warning(f"Scan already running for asset {asset_id}")
                return

            # Create scan record
            scan_obj = Scan(asset_id=asset.id, status="running", scan_type=scan_type)
            db.session.add(scan_obj)
            db.session.commit()
            logger.info(f"Starting scan for {asset.domain} (scan_id={scan_obj.id})")

            all_subs = set()
            urls = []
            ips = []
            all_urls = []

            try:
                # ---------- Subdomain discovery (parallel) ----------
                with ThreadPoolExecutor(max_workers=3) as executor:
                    futures = {
                        executor.submit(run_subfinder, asset): "subfinder",
                        executor.submit(run_amass, asset): "amass",
                        executor.submit(run_assetfinder, asset): "assetfinder"
                    }
                    for future in as_completed(futures):
                        tool = futures[future]
                        try:
                            result = future.result()
                            all_subs.update(result)
                            setattr(scan_obj, f"{tool}_status", "done")
                        except Exception as e:
                            logger.error(f"{tool} failed: {e}")
                            setattr(scan_obj, f"{tool}_status", "failed")
                        db.session.commit()

                # ---------- DNS resolution ----------
                try:
                    scan_obj.dnsx_status = "running"
                    db.session.commit()
                    run_dnsx(asset, list(all_subs))
                    scan_obj.dnsx_status = "done"
                except Exception as e:
                    logger.error(f"DNSx failed: {e}")
                    scan_obj.dnsx_status = "failed"
                db.session.commit()

                # ---------- Live host detection ----------
                targets = list(all_subs) + [asset.domain]
                try:
                    scan_obj.httpx_status = "running"
                    db.session.commit()
                    urls, ips = run_httpx(asset, targets)
                    scan_obj.httpx_status = "done"
                except Exception as e:
                    logger.error(f"Httpx failed: {e}")
                    scan_obj.httpx_status = "failed"
                db.session.commit()

                # Fallback URLs
                if not urls:
                    urls = [f"http://{asset.domain}", f"https://{asset.domain}"]
                all_urls = list(set(urls))

                # ---------- Port scanning ----------
                if ips:
                    try:
                        scan_obj.naabu_status = "running"
                        db.session.commit()
                        ports = run_naabu(asset, ips)
                        port_urls = convert_ports_to_urls(ports)
                        all_urls = list(set(all_urls + port_urls))
                        scan_obj.naabu_status = "done"
                    except Exception as e:
                        logger.error(f"Naabu failed: {e}")
                        scan_obj.naabu_status = "failed"
                    db.session.commit()
                else:
                    scan_obj.naabu_status = "skipped"
                    db.session.commit()

                # ---------- Endpoint discovery ----------
                try:
                    scan_obj.gau_status = "running"
                    db.session.commit()
                    historical = run_gau(asset)
                    all_urls = list(set(all_urls + historical))
                    scan_obj.gau_status = "done"
                except Exception as e:
                    logger.error(f"Gau failed: {e}")
                    scan_obj.gau_status = "failed"
                db.session.commit()

                if all_urls:
                    try:
                        scan_obj.katana_status = "running"
                        db.session.commit()
                        katana_urls = run_katana(asset, all_urls)
                        all_urls = list(set(all_urls + katana_urls))
                        scan_obj.katana_status = "done"
                    except Exception as e:
                        logger.error(f"Katana failed: {e}")
                        scan_obj.katana_status = "failed"
                    db.session.commit()
                else:
                    scan_obj.katana_status = "skipped"
                    db.session.commit()

                # ---------- Technology detection ----------
                if all_urls:
                    try:
                        scan_obj.whatweb_status = "running"
                        db.session.commit()
                        run_whatweb(asset, all_urls)
                        scan_obj.whatweb_status = "done"
                    except Exception as e:
                        logger.error(f"WhatWeb failed: {e}")
                        scan_obj.whatweb_status = "failed"
                    db.session.commit()

                    try:
                        scan_obj.wappalyzer_status = "running"
                        db.session.commit()
                        run_wappalyzer(asset, all_urls)
                        scan_obj.wappalyzer_status = "done"
                    except Exception as e:
                        logger.error(f"Wappalyzer failed: {e}")
                        scan_obj.wappalyzer_status = "failed"
                    db.session.commit()
                else:
                    scan_obj.whatweb_status = "skipped"
                    scan_obj.wappalyzer_status = "skipped"
                    db.session.commit()

                # ---------- Email discovery ----------
                try:
                    scan_obj.theharvester_status = "running"
                    db.session.commit()
                    run_theharvester(asset)
                    scan_obj.theharvester_status = "done"
                except Exception as e:
                    logger.error(f"TheHarvester failed: {e}")
                    scan_obj.theharvester_status = "failed"
                db.session.commit()

                # ---------- Takeover detection ----------
                if all_subs:
                    try:
                        scan_obj.subzy_status = "running"
                        db.session.commit()
                        run_subzy(asset, list(all_subs))
                        scan_obj.subzy_status = "done"
                    except Exception as e:
                        logger.error(f"Subzy failed: {e}")
                        scan_obj.subzy_status = "failed"
                    db.session.commit()
                else:
                    scan_obj.subzy_status = "skipped"
                    db.session.commit()

                # ---------- Vulnerability scanning ----------
                if all_urls:
                    try:
                        scan_obj.nuclei_status = "running"
                        db.session.commit()
                        run_nuclei(asset, all_urls)
                        scan_obj.nuclei_status = "done"
                    except Exception as e:
                        logger.error(f"Nuclei failed: {e}")
                        scan_obj.nuclei_status = "failed"
                    db.session.commit()
                else:
                    scan_obj.nuclei_status = "skipped"
                    db.session.commit()

                # ---------- Screenshots ----------
                if all_urls:
                    try:
                        scan_obj.gowitness_status = "running"
                        db.session.commit()
                        run_gowitness(asset, all_urls[:20])
                        scan_obj.gowitness_status = "done"
                    except Exception as e:
                        logger.error(f"Gowitness failed: {e}")
                        scan_obj.gowitness_status = "failed"
                    db.session.commit()
                else:
                    scan_obj.gowitness_status = "skipped"
                    db.session.commit()

                # All done
                scan_obj.status = "completed"
                logger.info(f"Scan completed for {asset.domain}")

            except Exception as e:
                db.session.rollback()
                scan_obj.status = "failed"
                scan_obj.error_message = str(e)
                logger.exception(f"Unhandled scan error for {asset.domain}")
            finally:
                scan_obj.finished_at = datetime.now(timezone.utc)
                db.session.commit()
                asset.update_risk_score()
                db.session.commit()
                logger.info(f"Final risk score for {asset.domain}: {asset.risk_score}")

# ================= SCHEDULED SCANS =================
def scheduled_scan_runner(app):
    with app.app_context():
        logger.info("Scheduler checking assets...")
        now = datetime.now(timezone.utc)
        assets = Asset.query.filter_by(monitoring_enabled=True).all()
        for asset in assets:
            freq = asset.monitoring_frequency
            if not freq or freq == "manual":
                continue
            should_run = False
            last = asset.last_monitored_at
            if last is None:
                should_run = True
            else:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                delta = now - last
                if freq == "hourly" and delta.total_seconds() >= 3600:
                    should_run = True
                elif freq == "daily" and delta.total_seconds() >= 86400:
                    should_run = True
                elif freq == "weekly" and delta.total_seconds() >= 604800:
                    should_run = True
                elif freq == "monthly" and delta.days >= 30:
                    should_run = True
                elif freq == "yearly" and delta.days >= 365:
                    should_run = True
            if should_run:
                logger.info(f"Triggering scheduled scan for {asset.domain}")
                thread = threading.Thread(target=background_scan, args=(app, asset.id), kwargs={"scan_type": "scheduled"}, daemon=True)
                thread.start()
                asset.last_monitored_at = now
                db.session.commit()
                log_activity(action="AUTO_SCHEDULE_SCAN", target=asset.domain, severity="INFO")

# ================= FLASK APP =================
def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    db.init_app(app)
    scheduler.init_app(app)

    @app.after_request
    def add_security_headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        return resp

    register_routes(app)
    return app

def register_routes(app):
    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/logout")
    def logout():
        log_activity("USER_LOGOUT", session.get("username", "unknown"))
        session.clear()
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                session["user_id"] = user.id
                session["role"] = user.role
                session["username"] = user.username
                log_activity("USER_LOGIN", username)
                if user.role == "admin":
                    return redirect(url_for("dashboard"))
                else:
                    return redirect(url_for("analyst_dashboard"))
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
        return render_template("login.html")

    # ================= ANALYST DASHBOARD (Enhanced) =================
    @app.route("/analyst_dashboard")
    @login_required
    @role_required("analyst")
    def analyst_dashboard():
        assets = Asset.query.all()
        # Compute counts and severity for each asset (similar to admin dashboard)
        approved_counts = dict(db.session.query(AssetInventory.parent_asset_id, func.count(AssetInventory.id)).filter_by(status='approved').group_by(AssetInventory.parent_asset_id).all())
        shadow_counts = dict(db.session.query(AssetInventory.parent_asset_id, func.count(AssetInventory.id)).filter_by(status='shadow').group_by(AssetInventory.parent_asset_id).all())
        severity_rows = db.session.query(Vulnerability.asset_id, Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.asset_id, Vulnerability.severity).all()
        severity_counts = defaultdict(dict)
        for asset_id, severity, cnt in severity_rows:
            severity_counts[asset_id][severity] = cnt
        subq = db.session.query(Scan.asset_id, func.max(Scan.id).label('max_id')).group_by(Scan.asset_id).subquery()
        last_scans = db.session.query(Scan).join(subq, (Scan.asset_id == subq.c.asset_id) & (Scan.id == subq.c.max_id)).all()
        asset_scans = {s.asset_id: s for s in last_scans}
        return render_template("analyst_dashboard.html",
                               assets=assets,
                               approved_counts=approved_counts,
                               shadow_counts=shadow_counts,
                               severity_counts=severity_counts,
                               asset_scans=asset_scans,
                               risk_level=get_risk_level)

    # ================= ADMIN DASHBOARD =================
    @app.route("/dashboard")
    @login_required
    def dashboard():
        assets = Asset.query.all()
        approved_counts = dict(db.session.query(AssetInventory.parent_asset_id, func.count(AssetInventory.id)).filter_by(status='approved').group_by(AssetInventory.parent_asset_id).all())
        shadow_counts = dict(db.session.query(AssetInventory.parent_asset_id, func.count(AssetInventory.id)).filter_by(status='shadow').group_by(AssetInventory.parent_asset_id).all())
        severity_rows = db.session.query(Vulnerability.asset_id, Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.asset_id, Vulnerability.severity).all()
        severity_counts = defaultdict(dict)
        for asset_id, severity, cnt in severity_rows:
            severity_counts[asset_id][severity] = cnt
        subq = db.session.query(Scan.asset_id, func.max(Scan.id).label('max_id')).group_by(Scan.asset_id).subquery()
        last_scans = db.session.query(Scan).join(subq, (Scan.asset_id == subq.c.asset_id) & (Scan.id == subq.c.max_id)).all()
        asset_scans = {s.asset_id: s for s in last_scans}
        return render_template("dashboard.html", assets=assets, asset_scans=asset_scans,
                               approved_counts=approved_counts, shadow_counts=shadow_counts,
                               severity_counts=severity_counts, risk_level=get_risk_level)

    # ================= USER MANAGEMENT (Admin only) =================
    @app.route("/admin/users")
    @login_required
    @role_required("admin")
    def admin_users():
        users = User.query.all()
        return render_template("admin_users.html", users=users)

    @app.route("/add-user", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def add_user_route():
        if request.method == "POST":
            username = request.form.get("username").strip()
            password = request.form.get("password").strip()
            role = request.form.get("role").strip()
            if not username or not password or not role:
                return "All fields are required", 400
            if User.query.filter_by(username=username).first():
                return "User already exists", 400
            is_strong, msg = is_strong_password(password)
            if not is_strong:
                return msg, 400
            new_user = User(username=username, password=generate_password_hash(password), role=role)
            db.session.add(new_user)
            db.session.commit()
            log_activity("CREATE_USER", username)
            return redirect(url_for("admin_users"))
        return render_template("add_user.html")

    @app.route("/delete-user/<int:user_id>")
    @login_required
    @role_required("admin")
    def delete_user(user_id):
        user = db.session.get(User, user_id)
        if not user:
            abort(404)
        if user.username == "admin":
            return "Cannot delete default admin", 403
        db.session.delete(user)
        db.session.commit()
        log_activity("DELETE_USER", user.username)
        return redirect(url_for("admin_users"))

    @app.route("/admin/users/edit/<int:user_id>", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def edit_user(user_id):
        user = db.session.get(User, user_id)
        if not user:
            abort(404)
        if request.method == "POST":
            username = request.form.get("username")
            role = request.form.get("role")
            password = request.form.get("password")
            if username:
                user.username = username
            if role:
                user.role = role
            if password:
                is_strong, msg = is_strong_password(password)
                if not is_strong:
                    return msg, 400
                user.password = generate_password_hash(password)
            db.session.commit()
            log_activity("EDIT_USER", user.username, severity="MEDIUM")
            return redirect(url_for("admin_users"))
        return render_template("edit_user.html", user=user)

    # ================= ASSET MANAGEMENT (Admin only) =================
    @app.route("/add-asset", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def add_asset():
        if request.method == "POST":
            domain = request.form.get("domain", "").strip()
            if not is_valid_domain(domain):
                flash("Invalid domain format.", "danger")
                return redirect(url_for("add_asset"))
            subdomains = [s.strip() for s in request.form.get("subdomains", "").split(",") if s.strip()]
            urls = [u.strip() for u in request.form.get("urls", "").split(",") if u.strip() and is_valid_url(u)]
            ips = [i.strip() for i in request.form.get("ips", "").split(",") if i.strip() and is_valid_ip(i)]
            ports = [p.strip() for p in request.form.get("ports", "").split(",") if p.strip() and is_valid_port(p)]
            services = [s.strip() for s in request.form.get("services", "").split(",") if s.strip()]
            technologies = [t.strip() for t in request.form.get("technologies", "").split(",") if t.strip()]
            emails = [e.strip() for e in request.form.get("emails", "").split(",") if e.strip()]
            valid_emails = []
            email_regex = r'^[^@]+@[^@]+\.[^@]+$'
            for email in emails:
                if re.match(email_regex, email):
                    valid_emails.append(email)
                else:
                    flash(f"Invalid email address '{email}' skipped.", "warning")
            cloud_assets = [c.strip() for c in request.form.get("cloud_assets", "").split(",") if c.strip()]
            api_endpoints = [a.strip() for a in request.form.get("api_endpoints", "").split(",") if a.strip() and is_valid_url(a)]
            subdomains = list(set(subdomains))
            urls = list(set(urls))
            ips = list(set(ips))
            ports = list(set(ports))
            services = list(set(services))
            technologies = list(set(technologies))
            valid_emails = list(set(valid_emails))
            cloud_assets = list(set(cloud_assets))
            api_endpoints = list(set(api_endpoints))

            if Asset.query.filter_by(domain=domain).first():
                flash("Asset with this domain already exists.", "warning")
                return redirect(url_for("dashboard"))

            new_asset = Asset(domain=domain)
            db.session.add(new_asset)
            db.session.commit()

            inventory_items = []
            inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="domain", value=domain, status="approved", discovered_by="manual"))
            for sub in subdomains:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="subdomain", value=sub, status="approved", discovered_by="manual"))
            for url in urls:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="url", value=url, status="approved", discovered_by="manual"))
            for ip in ips:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="ip", value=ip, status="approved", discovered_by="manual"))
            for port in ports:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="port", value=port, status="approved", discovered_by="manual"))
            for svc in services:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="service", value=svc, status="approved", discovered_by="manual"))
            for tech in technologies:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="technology", value=tech, status="approved", discovered_by="manual"))
            for email in valid_emails:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="email", value=email, status="approved", discovered_by="manual"))
            for cloud in cloud_assets:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="cloud_asset", value=cloud, status="approved", discovered_by="manual"))
            for api in api_endpoints:
                inventory_items.append(AssetInventory(parent_asset_id=new_asset.id, asset_type="api_endpoint", value=api, status="approved", discovered_by="manual"))

            db.session.bulk_save_objects(inventory_items)
            db.session.commit()
            log_activity("ADD_ASSET", domain)
            flash(f"Asset '{domain}' added successfully!", "success")
            return redirect(url_for("dashboard"))
        return render_template("add_asset.html")

    @app.route("/asset/<int:asset_id>")
    @login_required
    def view_asset(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        inventory = AssetInventory.query.filter_by(parent_asset_id=asset.id).order_by(AssetInventory.asset_type, AssetInventory.status.desc()).all()
        log_activity("VIEW_ASSET", asset.domain)
        return render_template("asset_detail.html", asset=asset, inventory=inventory)

    @app.route("/scan/<int:asset_id>")
    @login_required
    @role_required("admin", "analyst")
    def scan_asset(asset_id):
        if Scan.query.filter_by(asset_id=asset_id, status="running").first():
            flash("Scan already running.", "warning")
            return redirect(url_for("dashboard") if session.get("role") == "admin" else url_for("analyst_dashboard"))
        thread = threading.Thread(target=background_scan, args=(current_app._get_current_object(), asset_id), kwargs={"scan_type": "manual"}, daemon=True)
        thread.start()
        log_activity("START_SCAN", f"Asset ID {asset_id}")
        flash("Scan started.", "success")
        return redirect(url_for("dashboard") if session.get("role") == "admin" else url_for("analyst_dashboard"))

    @app.route("/admin/schedule/<int:asset_id>", methods=["POST"])
    @login_required
    @role_required("admin")
    def update_schedule(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        frequency = request.form.get("frequency")
        run_now = request.form.get("run_now")
        asset.monitoring_frequency = frequency
        asset.monitoring_enabled = frequency != "manual"
        asset.last_monitored_at = None
        db.session.commit()
        if run_now:
            thread = threading.Thread(target=background_scan, args=(current_app._get_current_object(), asset.id), kwargs={"scan_type": "manual"}, daemon=True)
            thread.start()
            log_activity("IMMEDIATE_SCAN_TRIGGERED", asset.domain)
        flash("Schedule updated!", "success")
        return redirect(url_for("dashboard"))

    @app.route("/toggle-schedule/<int:asset_id>")
    @login_required
    @role_required("admin")
    def toggle_schedule(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        asset.monitoring_enabled = not asset.monitoring_enabled
        db.session.commit()
        status = "enabled" if asset.monitoring_enabled else "disabled"
        log_activity("TOGGLE_SCHEDULE", asset.domain, details=f"Scheduled scanning {status}")
        flash(f"Scheduled scanning {status} for {asset.domain}.", "success")
        return redirect(request.referrer or url_for("dashboard"))

    @app.route("/vulnerabilities/<int:asset_id>")
    @login_required
    def view_vulnerabilities(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        vulns = Vulnerability.query.filter_by(asset_id=asset_id).order_by(Vulnerability.matched_at.desc()).all()
        last_scan = Scan.query.filter_by(asset_id=asset_id).order_by(Scan.id.desc()).first()
        scan_status = last_scan.status if last_scan else "not_started"
        dashboard_url = "analyst_dashboard" if session.get("role") == "analyst" else "dashboard"
        return render_template("vulnerabilities.html", vulns=vulns, asset=asset, scan_status=scan_status, dashboard_url=dashboard_url)

    @app.route("/vulnerability/<int:vuln_id>/note", methods=["POST"])
    @login_required
    @role_required("admin", "analyst")
    def add_vulnerability_note(vuln_id):
        vuln = db.session.get(Vulnerability, vuln_id)
        if not vuln:
            abort(404)
        note = request.form.get("note", "").strip()
        if note:
            vuln.notes = note
            db.session.commit()
            log_activity("ADD_VULN_NOTE", vuln.name, details=f"Added note: {note[:50]}")
            flash("Note added.", "success")
        else:
            flash("Note cannot be empty.", "warning")
        return redirect(request.referrer or url_for("view_vulnerabilities", asset_id=vuln.asset_id))

    @app.route("/shadows")
    @login_required
    def view_shadows():
        shadows = AssetInventory.query.filter_by(status="shadow").order_by(AssetInventory.created_at.desc()).all()
        log_activity("VIEW_SHADOWS", "ALL")
        return render_template("shadows.html", shadows=shadows)

    @app.route("/approve/<int:item_id>")
    @login_required
    @role_required("admin")
    def approve_shadow(item_id):
        item = db.session.get(AssetInventory, item_id)
        if not item:
            abort(404)
        item.status = "approved"
        db.session.commit()
        log_activity("APPROVE_SHADOW_ASSET", item.value, severity="MEDIUM")
        return redirect(url_for("view_shadows"))

    @app.route("/reject/<int:item_id>")
    @login_required
    @role_required("admin")
    def reject_shadow(item_id):
        item = db.session.get(AssetInventory, item_id)
        if not item:
            abort(404)
        item.status = "rejected"
        db.session.commit()
        log_activity("REJECT_SHADOW_ASSET", item.value, severity="WARNING")
        return redirect(url_for("view_shadows"))

    @app.route("/admin/edit-asset/<int:asset_id>", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    def edit_asset(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        inventory = AssetInventory.query.filter_by(parent_asset_id=asset.id).all()
        subdomains = [i.value for i in inventory if i.asset_type == "subdomain"]
        server_ips = [i.value for i in inventory if i.asset_type == "ip"]
        open_ports = [i.value for i in inventory if i.asset_type == "port"]
        urls = [i.value for i in inventory if i.asset_type == "url"]
        if request.method == "POST":
            new_domain = request.form.get("domain", "").strip()
            if new_domain and new_domain != asset.domain:
                if not is_valid_domain(new_domain):
                    flash("Invalid domain format.", "danger")
                    return redirect(url_for("edit_asset", asset_id=asset.id))
                asset.domain = new_domain
                db.session.commit()
                log_activity("UPDATE_ASSET_DOMAIN", f"{asset.domain} -> {new_domain}", severity="MEDIUM")

            def update_inventory(field_name, asset_type, validator=None):
                raw = request.form.get(field_name, "").splitlines()
                values = [v.strip() for v in raw if v.strip()]
                if validator:
                    values = [v for v in values if validator(v)]
                AssetInventory.query.filter_by(parent_asset_id=asset.id, asset_type=asset_type).delete()
                items = [AssetInventory(parent_asset_id=asset.id, asset_type=asset_type, value=v, status="approved", discovered_by="manual") for v in values]
                db.session.bulk_save_objects(items)

            update_inventory("subdomains", "subdomain")
            update_inventory("server_ips", "ip", is_valid_ip)
            update_inventory("open_ports", "port", is_valid_port)
            update_inventory("urls", "url", is_valid_url)
            db.session.commit()
            flash("Asset updated successfully!", "success")
            return redirect(url_for("dashboard"))
        return render_template("edit_asset.html", asset=asset, subdomains="\n".join(subdomains),
                               server_ips="\n".join(server_ips), open_ports="\n".join(open_ports), urls="\n".join(urls))

    @app.route("/delete/<int:asset_id>")
    @login_required
    @role_required("admin")
    def delete_asset(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        AssetInventory.query.filter_by(parent_asset_id=asset.id).delete()
        Scan.query.filter_by(asset_id=asset.id).delete()
        Vulnerability.query.filter_by(asset_id=asset.id).delete()
        db.session.delete(asset)
        db.session.commit()
        log_activity("DELETE_ASSET", asset.domain, severity="HIGH")
        return redirect(url_for("dashboard"))

    @app.route("/stop/<int:scan_id>")
    @login_required
    @role_required("admin")
    def stop_scan(scan_id):
        scan = db.session.get(Scan, scan_id)
        if scan and scan.status == "running":
            scan.status = "stopped"
            db.session.commit()
            flash("Scan marked as stopped. The background process may continue for a short time.", "warning")
        return redirect(url_for("dashboard"))

    @app.route("/admin/activity-logs")
    @login_required
    @role_required("admin")
    def activity_logs():
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(200).all()
        return render_template("activity_logs.html", logs=logs)

    @app.route("/admin/activity-logs/clear", methods=["POST"])
    @login_required
    @role_required("admin")
    def clear_activity_logs():
        try:
            num_deleted = ActivityLog.query.count()
            ActivityLog.query.delete()
            db.session.commit()
            log_activity("CLEAR_ACTIVITY_LOGS", "ALL", details=f"Cleared {num_deleted} logs", severity="MEDIUM")
            flash(f"Cleared {num_deleted} activity logs.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Failed to clear activity logs.", "danger")
        return redirect(url_for("activity_logs"))

    @app.route("/api/scan-progress/<int:asset_id>")
    @login_required
    def api_scan_progress(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        last_scan = Scan.query.filter_by(asset_id=asset.id).order_by(Scan.id.desc()).first()
        severity_counts = {sev: Vulnerability.query.filter_by(asset_id=asset.id, severity=sev).count() for sev in
                           ("critical", "high", "medium", "low", "info")}
        if not last_scan:
            return jsonify({
                "status": "not_started",
                "subfinder": "pending", "httpx": "pending", "nuclei": "pending",
                "amass": "pending", "assetfinder": "pending", "whatweb": "pending",
                "gowitness": "pending", "dnsx": "pending", "wappalyzer": "pending",
                "katana": "pending", "naabu": "pending", "subzy": "pending", "gau": "pending",
                "theharvester": "pending",
                "risk_score": asset.risk_score or 0, "severity_counts": severity_counts
            })
        return jsonify({
            "status": last_scan.status,
            "subfinder": last_scan.subfinder_status,
            "httpx": last_scan.httpx_status,
            "nuclei": last_scan.nuclei_status,
            "amass": last_scan.amass_status,
            "assetfinder": last_scan.assetfinder_status,
            "whatweb": last_scan.whatweb_status,
            "gowitness": last_scan.gowitness_status,
            "dnsx": last_scan.dnsx_status,
            "wappalyzer": last_scan.wappalyzer_status,
            "katana": last_scan.katana_status,
            "naabu": last_scan.naabu_status,
            "subzy": last_scan.subzy_status,
            "gau": last_scan.gau_status,
            "theharvester": last_scan.theharvester_status,
            "risk_score": asset.risk_score or 0,
            "severity_counts": severity_counts
        })

    @app.route("/report/<int:asset_id>")
    @login_required
    @role_required("admin", "analyst")
    def view_report(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)

        # Get scans
        scans = Scan.query.filter_by(asset_id=asset.id).order_by(Scan.id.desc()).all()

        # Get vulnerabilities
        vulnerabilities = Vulnerability.query.filter_by(asset_id=asset.id).order_by(
            Vulnerability.matched_at.desc()).all()

        # Get inventory
        inventory = AssetInventory.query.filter_by(parent_asset_id=asset.id).all()

        # Counts by type
        domains_count = sum(1 for i in inventory if i.asset_type == 'domain')
        subdomains_count = sum(1 for i in inventory if i.asset_type == 'subdomain')
        urls_count = sum(1 for i in inventory if i.asset_type == 'url')
        ips_count = sum(1 for i in inventory if i.asset_type == 'ip')
        ports_count = sum(1 for i in inventory if i.asset_type == 'port')
        services_count = sum(1 for i in inventory if i.asset_type == 'service')
        technologies_count = sum(1 for i in inventory if i.asset_type == 'technology')
        emails_count = sum(1 for i in inventory if i.asset_type == 'email')
        cloud_count = sum(1 for i in inventory if i.asset_type == 'cloud_asset')
        api_count = sum(1 for i in inventory if i.asset_type == 'api_endpoint')

        # Status counts
        approved_count = sum(1 for i in inventory if i.status == 'approved')
        shadow_count = sum(1 for i in inventory if i.status == 'shadow')

        # Vulnerability counts by severity
        vuln_counts = {
            'critical': sum(1 for v in vulnerabilities if v.severity == 'critical'),
            'high': sum(1 for v in vulnerabilities if v.severity == 'high'),
            'medium': sum(1 for v in vulnerabilities if v.severity == 'medium'),
            'low': sum(1 for v in vulnerabilities if v.severity == 'low'),
            'info': sum(1 for v in vulnerabilities if v.severity == 'info')
        }

        # Calculate contributions
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        vuln_contribution = sum(severity_weights.get(sev, 0) * cnt for sev, cnt in vuln_counts.items())
        shadow_contribution = min(shadow_count * 0.5, 10)
        service_contribution = min(services_count * 0.2, 10)
        tech_contribution = min(technologies_count * 0.1, 5)
        port_contribution = min(ports_count * 0.1, 5)

        # Risk score and level
        risk_score = asset.risk_score
        risk_level = get_risk_level(risk_score)

        return render_template(
            "report.html",
            asset=asset,
            scans=scans,
            vulnerabilities=vulnerabilities,
            inventory=inventory,
            domains_count=domains_count,
            subdomains_count=subdomains_count,
            urls_count=urls_count,
            ips_count=ips_count,
            ports_count=ports_count,
            services_count=services_count,
            technologies_count=technologies_count,
            emails_count=emails_count,
            cloud_count=cloud_count,
            api_count=api_count,
            approved_count=approved_count,
            shadow_count=shadow_count,
            vuln_counts=vuln_counts,
            vuln_contribution=vuln_contribution,
            shadow_contribution=shadow_contribution,
            service_contribution=service_contribution,
            tech_contribution=tech_contribution,
            port_contribution=port_contribution,
            risk_score=risk_score,
            risk_level=risk_level
        )
    @app.route("/asi")
    @login_required
    def attack_surface_intelligence():
        assets = Asset.query.all()
        total_assets = len(assets)
        all_inventory = AssetInventory.query.order_by(AssetInventory.created_at.desc()).limit(50).all()

        # Asset counts
        domains_count = AssetInventory.query.filter_by(asset_type='domain').count()
        subdomains_count = AssetInventory.query.filter_by(asset_type='subdomain').count()
        urls_count = AssetInventory.query.filter_by(asset_type='url').count()
        ips_count = AssetInventory.query.filter_by(asset_type='ip').count()
        ports_count = AssetInventory.query.filter_by(asset_type='port').count()
        services_count = AssetInventory.query.filter_by(asset_type='service').count()
        tech_count = AssetInventory.query.filter_by(asset_type='technology').count()
        email_count = AssetInventory.query.filter_by(asset_type='email').count()
        cloud_count = AssetInventory.query.filter_by(asset_type='cloud_asset').count()
        api_count = AssetInventory.query.filter_by(asset_type='api_endpoint').count()
        shadow_count = AssetInventory.query.filter_by(status='shadow').count()
        approved_count = AssetInventory.query.filter_by(status='approved').count()

        # Risk statistics
        avg_risk_score = db.session.query(func.avg(Asset.risk_score)).scalar() or 0
        max_risk_score = db.session.query(func.max(Asset.risk_score)).scalar() or 0
        max_risk_asset = Asset.query.order_by(Asset.risk_score.desc()).first()

        # Vulnerability statistics
        total_vulnerabilities = Vulnerability.query.count()
        critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
        high_vulns = Vulnerability.query.filter_by(severity='high').count()

        # Risk level counts
        extreme_risk = Asset.query.filter(Asset.risk_score >= 80).count()
        severe_risk = Asset.query.filter(Asset.risk_score.between(50, 79)).count()
        critical_risk = Asset.query.filter(Asset.risk_score.between(20, 49)).count()
        high_risk = Asset.query.filter(Asset.risk_score.between(10, 19)).count()
        medium_risk = Asset.query.filter(Asset.risk_score.between(5, 9)).count()
        low_risk = Asset.query.filter(Asset.risk_score.between(1, 4)).count()
        low_risk_count = low_risk + medium_risk
        no_risk = Asset.query.filter(Asset.risk_score == 0).count()

        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_discoveries = AssetInventory.query.filter(AssetInventory.created_at >= week_ago).count()
        top_risk_assets = Asset.query.order_by(Asset.risk_score.desc()).limit(5).all()

        # Charts
        charts = {}

        # Asset Type Distribution Chart
        fig1 = go.Figure(data=[go.Bar(
            x=['Domains', 'Subdomains', 'URLs', 'IPs', 'Ports', 'Services', 'Tech', 'Email', 'Cloud', 'API'],
            y=[domains_count, subdomains_count, urls_count, ips_count, ports_count, services_count, tech_count,
               email_count, cloud_count, api_count],
            marker_color=['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6', '#1abc9c', '#e67e22', '#34495e',
                          '#16a085', '#d35400']
        )])
        fig1.update_layout(title='Asset Type Distribution', xaxis_title='Asset Type', yaxis_title='Count',
                           template='plotly_dark', height=400)
        charts['type_distribution'] = json.dumps(fig1, cls=plotly.utils.PlotlyJSONEncoder)

        # Status Distribution Chart
        fig2 = go.Figure(data=[go.Pie(
            labels=['Approved', 'Shadow'],
            values=[approved_count, shadow_count],
            marker_colors=['#2ecc71', '#e74c3c'],
            hole=0.4
        )])
        fig2.update_layout(title='Asset Status Distribution', template='plotly_dark', height=400)
        charts['status_distribution'] = json.dumps(fig2, cls=plotly.utils.PlotlyJSONEncoder)

        # Risk Distribution Chart
        fig3 = go.Figure(data=[go.Bar(
            x=['Extreme (80+)', 'Severe (50-79)', 'Critical (20-49)', 'High (10-19)', 'Medium (5-9)', 'Low (1-4)',
               'None (0)'],
            y=[extreme_risk, severe_risk, critical_risk, high_risk, medium_risk, low_risk, no_risk],
            marker_color=['#8B0000', '#DC143C', '#e74c3c', '#e67e22', '#f1c40f', '#3498db', '#95a5a6'],
            text=[extreme_risk, severe_risk, critical_risk, high_risk, medium_risk, low_risk, no_risk],
            textposition='auto'
        )])
        fig3.update_layout(title='Asset Risk Distribution', xaxis_title='Risk Level', yaxis_title='Number of Assets',
                           template='plotly_dark', height=400)
        charts['risk_distribution'] = json.dumps(fig3, cls=plotly.utils.PlotlyJSONEncoder)

        # Timeline Chart
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        daily_counts = db.session.query(
            func.date(AssetInventory.created_at).label('date'),
            func.count().label('count')
        ).filter(AssetInventory.created_at >= thirty_days_ago).group_by(
            func.date(AssetInventory.created_at)
        ).order_by('date').all()

        dates = [str(d[0]) for d in daily_counts]
        counts = [d[1] for d in daily_counts]

        fig4 = go.Figure(data=[go.Scatter(
            x=dates,
            y=counts,
            mode='lines+markers',
            line=dict(color='#3498db', width=3),
            marker=dict(size=8)
        )])
        fig4.update_layout(title='Asset Discovery Timeline (Last 30 Days)', xaxis_title='Date',
                           yaxis_title='New Discoveries', template='plotly_dark', height=400)
        charts['timeline'] = json.dumps(fig4, cls=plotly.utils.PlotlyJSONEncoder)

        log_activity("VIEW_ASI_DASHBOARD", "Attack Surface Intelligence")

        return render_template(
            "asi_dashboard.html",
            assets=assets,
            inventory=all_inventory,
            total_assets=total_assets,
            domains_count=domains_count,
            subdomains_count=subdomains_count,
            urls_count=urls_count,
            ips_count=ips_count,
            ports_count=ports_count,
            services_count=services_count,
            tech_count=tech_count,
            email_count=email_count,
            cloud_count=cloud_count,
            api_count=api_count,
            shadow_count=shadow_count,
            approved_count=approved_count,
            recent_discoveries=recent_discoveries,
            top_risk_assets=top_risk_assets,
            extreme_risk=extreme_risk,
            severe_risk=severe_risk,
            critical_risk=critical_risk,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            low_risk_count=low_risk_count,
            no_risk=no_risk,
            avg_risk_score=avg_risk_score,
            max_risk_score=max_risk_score,
            max_risk_asset=max_risk_asset,
            total_vulnerabilities=total_vulnerabilities,
            critical_vulns=critical_vulns,
            high_vulns=high_vulns,
            charts=charts
        )
    @app.route("/asi/asset-map")
    @login_required
    def asset_map():
        assets = Asset.query.all()
        nodes, links = [], []
        for asset in assets:
            nodes.append({"id": f"asset_{asset.id}", "label": asset.domain, "group": "asset", "value": asset.risk_score,
                          "title": f"Risk Score: {asset.risk_score}\nCreated: {asset.created_at.strftime('%Y-%m-%d')}"})
            inventory = AssetInventory.query.filter_by(parent_asset_id=asset.id).all()
            for item in inventory:
                node_id = f"{item.asset_type}_{item.id}"
                nodes.append({"id": node_id, "label": item.value[:30] + "..." if len(item.value) > 30 else item.value,
                              "group": item.asset_type, "status": item.status,
                              "title": f"Type: {item.asset_type}\nStatus: {item.status}\nDiscovered: {item.discovered_by}\nDate: {item.created_at.strftime('%Y-%m-%d')}"})
                links.append({"from": f"asset_{asset.id}", "to": node_id, "label": item.asset_type, "arrows": "to"})
        return render_template("asset_map.html", nodes=json.dumps(nodes), links=json.dumps(links))

    @app.route("/asi/inventory/<asset_type>")
    @login_required
    def inventory_by_type(asset_type):
        valid_types = ['domain', 'subdomain', 'url', 'ip', 'port', 'service', 'technology', 'email', 'certificate',
                       'cloud_asset', 'api_endpoint', 'asn', 'registrar', 'organization', 'country', 'dns_txt']
        if asset_type not in valid_types:
            abort(404)
        icon_map = {
            "domain": "bi-globe", "subdomain": "bi-diagram-3", "url": "bi-link-45deg", "ip": "bi-hdd-network",
            "port": "bi-usb-symbol", "service": "bi-gear", "technology": "bi-cpu", "email": "bi-envelope",
            "certificate": "bi-shield-lock", "cloud_asset": "bi-cloud", "api_endpoint": "bi-code-slash",
            "asn": "bi-diagram-2", "registrar": "bi-building", "organization": "bi-people", "country": "bi-flag",
            "dns_txt": "bi-file-text"
        }
        inventory = AssetInventory.query.filter_by(asset_type=asset_type).order_by(AssetInventory.created_at.desc()).all()
        by_asset = defaultdict(list)
        for item in inventory:
            asset = Asset.query.get(item.parent_asset_id)
            if asset:
                by_asset[asset.domain].append(item)
        log_activity("VIEW_INVENTORY_TYPE", asset_type)
        return render_template("inventory_by_type.html", asset_type=asset_type, inventory=inventory,
                               by_asset=dict(by_asset), count=len(inventory), icon_map=icon_map)

    @app.route("/asi/stats")
    @login_required
    def asi_stats():
        type_counts = db.session.query(AssetInventory.asset_type, func.count().label('count')).group_by(AssetInventory.asset_type).all()
        status_counts = db.session.query(AssetInventory.status, func.count().label('count')).group_by(AssetInventory.status).all()
        top_ports = db.session.query(AssetInventory.value, func.count().label('count')).filter(AssetInventory.asset_type == 'port').group_by(AssetInventory.value).order_by(desc('count')).limit(10).all()
        top_ips = db.session.query(AssetInventory.value, func.count().label('count')).filter(AssetInventory.asset_type == 'ip').group_by(AssetInventory.value).order_by(desc('count')).limit(10).all()
        return jsonify({
            'type_counts': [{'type': t[0], 'count': t[1]} for t in type_counts],
            'status_counts': [{'status': s[0], 'count': s[1]} for s in status_counts],
            'top_ports': [{'port': p[0], 'count': p[1]} for p in top_ports],
            'top_ips': [{'ip': i[0], 'count': i[1]} for i in top_ips],
            'total_assets': Asset.query.count(),
            'total_inventory': AssetInventory.query.count()
        })

    @app.route("/asi/export")
    @login_required
    @role_required("admin")
    def export_asi():
        data = {'export_date': datetime.now(timezone.utc).isoformat(), 'total_assets': Asset.query.count(),
                'total_inventory': AssetInventory.query.count(), 'assets': []}
        for asset in Asset.query.all():
            asset_data = {'id': asset.id, 'domain': asset.domain, 'risk_score': asset.risk_score,
                          'created_at': asset.created_at.isoformat(), 'monitoring_enabled': asset.monitoring_enabled,
                          'inventory': []}
            for item in AssetInventory.query.filter_by(parent_asset_id=asset.id).all():
                asset_data['inventory'].append({
                    'type': item.asset_type, 'value': item.value, 'version': item.version,
                    'screenshot_path': item.screenshot_path, 'metadata': item.asset_metadata,
                    'status': item.status, 'discovered_by': item.discovered_by, 'created_at': item.created_at.isoformat()
                })
            data['assets'].append(asset_data)
        response = jsonify(data)
        response.headers['Content-Disposition'] = f'attachment; filename=asi_export_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.json'
        return response

    @app.route("/asi/dashboard/<int:asset_id>")
    @login_required
    def asset_dashboard(asset_id):
        asset = db.session.get(Asset, asset_id)
        if not asset:
            abort(404)
        inventory = AssetInventory.query.filter_by(parent_asset_id=asset.id).all()
        vulns = Vulnerability.query.filter_by(asset_id=asset.id).order_by(Vulnerability.matched_at.desc()).all()
        scans = Scan.query.filter_by(asset_id=asset.id).order_by(Scan.id.desc()).all()
        domains = sum(1 for i in inventory if i.asset_type == 'domain')
        subdomains = sum(1 for i in inventory if i.asset_type == 'subdomain')
        urls = sum(1 for i in inventory if i.asset_type == 'url')
        ips = sum(1 for i in inventory if i.asset_type == 'ip')
        ports = sum(1 for i in inventory if i.asset_type == 'port')
        services = sum(1 for i in inventory if i.asset_type == 'service')
        technologies = sum(1 for i in inventory if i.asset_type == 'technology')
        emails = sum(1 for i in inventory if i.asset_type == 'email')
        cloud = sum(1 for i in inventory if i.asset_type == 'cloud_asset')
        apis = sum(1 for i in inventory if i.asset_type == 'api_endpoint')
        shadow = sum(1 for i in inventory if i.status == 'shadow')
        approved = sum(1 for i in inventory if i.status == 'approved')
        return render_template("asset_dashboard.html", asset=asset, inventory=inventory, vulns=vulns, scans=scans,
                               domains=domains, subdomains=subdomains, urls=urls, ips=ips, ports=ports,
                               services=services, technologies=technologies, emails=emails, cloud=cloud, apis=apis,
                               shadow=shadow, approved=approved)

    @app.route("/test-nuclei/<path:test_url>")
    @login_required
    @role_required("admin")
    def test_nuclei(test_url):
        if not app.debug:
            abort(404)
        test_domain = test_url.replace('http://', '').replace('https://', '').split('/')[0]
        asset = Asset.query.filter_by(domain=test_domain).first()
        if not asset:
            asset = Asset(domain=test_domain)
            db.session.add(asset)
            db.session.commit()
        findings = run_nuclei(asset, [test_url])
        return jsonify({"asset_id": asset.id, "domain": asset.domain, "findings_count": len(findings), "findings": findings[:10]})

def create_default_users():
    if User.query.count() == 0:

        # 🔐 Strong password generator
        def random_strong_password():
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            while True:
                password = ''.join(secrets.choice(alphabet) for _ in range(12))
                if (
                    any(c.islower() for c in password) and
                    any(c.isupper() for c in password) and
                    any(c.isdigit() for c in password) and
                    any(c in "!@#$%^&*" for c in password)
                ):
                    return password

        # ✅ Generate passwords (FIXED)
        admin_pw = random_strong_password()
        analyst_pw = random_strong_password()

        # ✅ Create users
        admin_user = User(
            username="admin",
            password=generate_password_hash(admin_pw),
            role="admin"
        )

        analyst_user = User(
            username="analyst",
            password=generate_password_hash(analyst_pw),
            role="analyst"
        )

        # ✅ Save to database
        db.session.add(admin_user)
        db.session.add(analyst_user)
        db.session.commit()

        print("\n✅ Default users created successfully!")
        print(f"👤 Admin username: admin | Password: {admin_pw}")
        print(f"👤 Analyst username: analyst | Password: {analyst_pw}")

# ================= MAIN =================
if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
        create_default_users()
        scheduler.start()
        if not scheduler.get_job("scheduled_scan_job"):
            scheduler.add_job(id="scheduled_scan_job", func=scheduled_scan_runner, args=(app,), trigger="interval", minutes=5, replace_existing=True)
    debug_mode = os.environ.get("FLASK_DEBUG", "TRUE").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
