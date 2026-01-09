import os
import shutil
import re
import sys
import csv
import json
import time
import queue
import math
import socket
import threading
import datetime
import urllib.parse
import subprocess
from dataclasses import dataclass
from typing import Optional, Set, Dict, Tuple, List

import requests
from dnslib import DNSRecord, QTYPE, RCODE, RR, A, AAAA
from dnslib.server import DNSServer, BaseResolver

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import pystray
from PIL import Image, ImageTk, ImageDraw, ImageFont

# Optional QR decode
import cv2

# Reports
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

APP_NAME = "BaitBuster Desktop Pro+"
APP_VERSION = "2.1.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
LOG_DIR = os.path.join(DATA_DIR, "logs")
QUAR_DIR = os.path.join(DATA_DIR, "quarantine")

DNS_BIND_IP = "127.0.0.1"
DNS_BIND_PORT = 53  # requires admin on Windows
DEFAULT_UPSTREAM = ("1.1.1.1", 53)

CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
CUSTOM_BLOCKLIST_PATH = os.path.join(DATA_DIR, "custom_blocklist.txt")
ALLOWLIST_PATH = os.path.join(DATA_DIR, "allowlist.txt")

BLOCKLIST_SOURCES = {
  "phishing": ["https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt"],
  "ads": ["https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt"],
  "tracking": ["https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt"],
}

SUSPICIOUS_KEYWORDS = [
  "login","verify","verification","update","secure","account","password","reset","unlock","invoice","payment",
  "bank","wallet","gcash","paypal","confirm","urgent","limited","suspend","security","validate","kyc",
  "otp","code","award","prize","gift","free","promo","claim","delivery","dhl","fedex","refund"
]

SUSPICIOUS_TLDS = {"zip","mov","top","xyz","click","country","stream","gq","tk","ml","cf","ga","work","support","live","icu","cam"}
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","cutt.ly","rebrand.ly","rb.gy","buff.ly","lnkd.in"}

DANGEROUS_EXTS = {"exe","scr","js","vbs","bat","cmd","ps1","jar","msi","iso","img","apk","dmg","pkg","lnk","hta","zip","7z","rar"}
DANGEROUS_MIME_HINTS = {"application/x-msdownload","application/octet-stream","application/x-sh","application/x-bat"}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^(https?://|www\.)", re.I)

# small brand set for typosquatting hints (editable)
BRANDS = [
  "google.com","gmail.com","microsoft.com","office.com","live.com","outlook.com",
  "facebook.com","messenger.com","instagram.com","whatsapp.com",
  "paypal.com","gcash.com","bpi.com.ph","bdo.com.ph","securitybank.com.ph","unionbankph.com",
  "lazada.com.ph","shopee.ph","dhl.com","fedex.com","apple.com"
]

HOMOGLYPHS = {
  "0":"o", "1":"l", "3":"e", "5":"s", "7":"t",
  "о":"o", "і":"i", "ӏ":"l", "а":"a", "е":"e", "р":"p", "с":"c", "х":"x", "у":"y",
}

def utc_iso():
  return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def parse_utc_iso(s: str) -> Optional[datetime.datetime]:
  try:
    if not s: return None
    if s.endswith("Z"):
      s = s.replace("Z","+00:00")
    return datetime.datetime.fromisoformat(s)
  except Exception:
    return None

def ensure_dirs():
  for p in (DATA_DIR, CACHE_DIR, LOG_DIR, QUAR_DIR):
    os.makedirs(p, exist_ok=True)
  for p, seed in (
    (CUSTOM_BLOCKLIST_PATH, "# one domain per line\n# badsite.com\n"),
    (ALLOWLIST_PATH, "# allowlist domains (never block)\n# example.com\n"),
  ):
    if not os.path.exists(p):
      with open(p, "w", encoding="utf-8") as f:
        f.write(seed)

def log_event(evt: dict):
  ensure_dirs()
  path = os.path.join(LOG_DIR, "events.jsonl")
  evt = dict(evt)
  evt["ts"] = evt.get("ts") or utc_iso()
  with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(evt, ensure_ascii=False) + "\n")

def normalize_domain(d: str) -> str:
  d = (d or "").strip().lower().rstrip(".")
  d = re.sub(r"^\*\.", "", d)
  return d

def extract_domain_line(line: str) -> Optional[str]:
  line = line.strip()
  if not line or line.startswith("#"): return None
  line = line.split("#",1)[0].strip()
  parts = line.split()
  if len(parts) == 1:
    cand = parts[0]
  else:
    cand = parts[1] if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parts[0]) else parts[0]
  cand = normalize_domain(cand)
  if not cand or cand == "localhost": return None
  if DOMAIN_RE.match(cand) is None: return None
  return cand

def cache_path_for(url: str) -> str:
  safe = re.sub(r"[^a-z0-9]+", "_", url.lower()).strip("_")
  return os.path.join(CACHE_DIR, safe + ".txt")

def download_text(url: str, timeout=12) -> Optional[str]:
  try:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": f"BaitBusterDesktopProPlus/{APP_VERSION}"})
    if r.status_code != 200: return None
    return r.text
  except Exception:
    return None

def read_domain_file(path: str) -> Set[str]:
  out=set()
  try:
    with open(path, "r", encoding="utf-8") as f:
      for line in f:
        d = extract_domain_line(line)
        if d: out.add(d)
  except Exception:
    pass
  return out

def parse_remote_blocklist(text: str) -> Set[str]:
  out=set()
  for line in (text or "").splitlines():
    d = extract_domain_line(line)
    if d: out.add(d)
  return out

def is_windows():
  return sys.platform.startswith("win")

def run_cmd(cmd: str) -> Tuple[int,str]:
  p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
  out = (p.stdout or "") + "\n" + (p.stderr or "")
  return p.returncode, out.strip()

def win_active_iface() -> Optional[str]:
  code, out = run_cmd("netsh interface show interface")
  if code != 0:
    return None
  for line in out.splitlines():
    if "Connected" in line and "Loopback" not in line:
      parts = re.split(r"\s{2,}", line.strip())
      if len(parts) >= 4:
        return parts[-1]
  return None

def win_dns_set_local(iface: str) -> Tuple[bool,str]:
  code, out = run_cmd(f'netsh interface ip set dns name="{iface}" static {DNS_BIND_IP} primary')
  return (code == 0), (out or "OK")

def win_dns_reset_dhcp(iface: str) -> Tuple[bool,str]:
  code, out = run_cmd(f'netsh interface ip set dns name="{iface}" dhcp')
  return (code == 0), (out or "OK")

def win_get_dns_servers(iface: str) -> List[str]:
  code, out = run_cmd("ipconfig /all")
  if code != 0:
    return []
  dns=[]
  lines = out.splitlines()
  in_iface=False
  for ln in lines:
    if ln.strip().endswith(":") and "adapter" in ln.lower():
      in_iface = iface.lower() in ln.lower()
      continue
    if not in_iface:
      continue
    if "DNS Servers" in ln and ":" in ln:
      v = ln.split(":")[-1].strip()
      if v: dns.append(v)
      continue
    if dns and ln.startswith("   ") and re.match(r"^\s+\d", ln):
      v = ln.strip()
      if v: dns.append(v)
  return dns

def windows_dns_is_pointing_localhost() -> bool:
  iface = win_active_iface()
  if not iface:
    return False
  servers = win_get_dns_servers(iface)
  return any(s.strip() == "127.0.0.1" for s in servers)

def looks_like_url(s: str) -> bool:
  if not s: return False
  s=s.strip()
  if len(s) < 6 or len(s) > 4096: return False
  return bool(URL_RE.match(s)) or ("." in s and "/" in s)

def sanitize_url(s: str) -> str:
  s=(s or "").strip()
  s=s.strip(" \t\r\n<>[]()\"'")
  return s

def is_ip_host(host: str) -> bool:
  for fam in (socket.AF_INET, socket.AF_INET6):
    try:
      socket.inet_pton(fam, host)
      return True
    except Exception:
      pass
  return False

def levenshtein(a: str, b: str) -> int:
  if a == b: return 0
  if not a: return len(b)
  if not b: return len(a)
  prev = list(range(len(b)+1))
  for i, ca in enumerate(a, 1):
    cur = [i]
    for j, cb in enumerate(b, 1):
      ins = cur[j-1] + 1
      dele = prev[j] + 1
      sub = prev[j-1] + (0 if ca == cb else 1)
      cur.append(min(ins, dele, sub))
    prev = cur
  return prev[-1]

def dehomoglyph(s: str) -> str:
  return "".join(HOMOGLYPHS.get(ch, ch) for ch in s)

@dataclass
class ScanResult:
  input: str
  normalized: str
  host: str
  score: int
  verdict: str
  reasons: List[str]
  expanded: Optional[str] = None

def verdict(score: int) -> str:
  if score >= 75: return "CRITICAL"
  if score >= 50: return "HIGH"
  if score >= 25: return "MEDIUM"
  return "LOW"

def expand_shortener(url: str, timeout=8) -> Optional[str]:
  try:
    r = requests.head(url, allow_redirects=True, timeout=timeout, headers={"User-Agent": f"BaitBusterDesktopProPlus/{APP_VERSION}"})
    return r.url
  except Exception:
    try:
      r = requests.get(url, allow_redirects=True, timeout=timeout, headers={"User-Agent": f"BaitBusterDesktopProPlus/{APP_VERSION}"})
      return r.url
    except Exception:
      return None

def analyze_url(url: str, blocked: Set[str], allow: Set[str], enable_expand: bool, explain: Dict[str,str]) -> ScanResult:
  raw = sanitize_url(url)
  reasons=[]
  score=0
  expanded=None

  if not raw:
    return ScanResult(url,"","",0,"EMPTY",["No URL provided"])

  if re.match(r"^\s*(javascript|data|vbscript|file):", raw, re.I):
    score += 90; reasons.append("Dangerous scheme (javascript/data/file).")

  has_scheme = bool(re.match(r"^[a-z][a-z0-9+\-.]*://", raw, re.I))
  parse_target = raw if has_scheme else "https://" + raw.lstrip("/")
  if not has_scheme:
    score += 8; reasons.append("No scheme provided (often hides destination).")

  parse_target = parse_target.strip(" \t\r\n<>[]()")
  try:
    parts = urllib.parse.urlsplit(parse_target)
  except Exception:
    score += 40; reasons.append("URL parsing failed.")
    return ScanResult(url, parse_target, "", min(100,score), verdict(min(100,score)), sorted(set(reasons)))

  host = (parts.hostname or "").lower()
  scheme = (parts.scheme or "https").lower()
  path = parts.path or "/"
  query = parts.query or ""

  if not host:
    score += 40; reasons.append("Missing host.")
    return ScanResult(url, parse_target, "", min(100,score), verdict(min(100,score)), sorted(set(reasons)))

  if enable_expand and host in SHORTENERS and scheme in ("http","https"):
    ex = expand_shortener(parse_target)
    if ex and ex != parse_target:
      expanded = ex
      reasons.append("Expanded shortener redirect.")
      try:
        parts2 = urllib.parse.urlsplit(ex)
        if parts2.hostname:
          host = parts2.hostname.lower()
          scheme = parts2.scheme.lower()
          path = parts2.path or "/"
          query = parts2.query or ""
      except Exception:
        pass

  norm = f"{scheme}://{host}{path}"
  if query: norm += "?" + query

  dom = normalize_domain(host)

  if dom in allow:
    return ScanResult(url, norm, dom, 0, "ALLOWLIST", ["Allowlisted domain."], expanded=expanded)

  # Typosquatting / homoglyph hints
  dom_ascii = dehomoglyph(dom)
  best = None
  best_dist = 999
  for b in BRANDS:
    d = levenshtein(dom_ascii, b)
    if d < best_dist:
      best_dist = d
      best = b
  if best and best_dist in (1,2) and dom_ascii != best:
    score += 18
    reasons.append(f"Possible typosquat/lookalike of {best} (distance={best_dist}).")

  if any(ch in HOMOGLYPHS for ch in dom):
    score += 10; reasons.append("Potential homoglyph characters in domain.")

  if "@" in parse_target:
    score += 25; reasons.append("Contains '@' trick.")
  if scheme == "http":
    score += 12; reasons.append("Plain HTTP (no TLS).")
  if len(parse_target) > 140:
    score += 8; reasons.append("Very long URL.")
  if any(ord(c) > 127 for c in parse_target):
    score += 10; reasons.append("Non-ASCII characters in URL (homograph risk).")
  if is_ip_host(host):
    score += 35; reasons.append("Host is an IP address.")

  labels=[p for p in dom.split(".") if p]
  if len(labels) >= 4:
    score += 8; reasons.append("Many subdomains (possible impersonation).")
  tld = labels[-1] if labels else ""
  if tld in SUSPICIOUS_TLDS:
    score += 12; reasons.append(f"High-risk TLD .{tld}.")
  if dom in SHORTENERS:
    score += 22; reasons.append("URL shortener hides destination.")

  ext = (os.path.splitext(urllib.parse.unquote(path))[1] or "").lstrip(".").lower()
  if ext and ext in DANGEROUS_EXTS:
    score += 28; reasons.append(f"Potentially risky download extension .{ext}.")

  hay = (path + "?" + query).lower()
  hits = sum(1 for k in SUSPICIOUS_KEYWORDS if k in hay)
  if hits:
    score += min(18, 3*hits); reasons.append("Phishy keywords in path/query.")

  # Optional lightweight HEAD check for download hints (safe: headers only)
  if scheme in ("http","https"):
    try:
      r = requests.head(parse_target, allow_redirects=True, timeout=6, headers={"User-Agent": f"BaitBusterDesktopProPlus/{APP_VERSION}"})
      ct = (r.headers.get("Content-Type","") or "").split(";")[0].strip().lower()
      cd = (r.headers.get("Content-Disposition","") or "").lower()
      if ct in DANGEROUS_MIME_HINTS or ("attachment" in cd):
        score += 20
        reasons.append("Response headers suggest a file download (Content-Type/Disposition).")
    except Exception:
      pass

  # Blocklist: exact or parent
  is_blocked = dom in blocked
  if not is_blocked:
    parts_d = dom.split(".")
    for i in range(1, len(parts_d)):
      if ".".join(parts_d[i:]) in blocked:
        is_blocked = True; break
  if is_blocked:
    score = max(score, 85)
    src = explain.get(dom) or "blocklist"
    reasons.append(f"Domain appears in blocklist ({src}).")

  score = max(0, min(100, score))
  return ScanResult(url, norm, dom, score, verdict(score), sorted(set(reasons)), expanded=expanded)

class FilterResolver(BaseResolver):
  def __init__(self, state): self.state=state
  def resolve(self, request, handler):
    qname = str(request.q.qname).rstrip(".").lower()
    qtype = QTYPE[request.q.qtype]
    domain = normalize_domain(qname)

    # track "new domain spikes" for non-blocked domains too
    self.state.observe(domain)

    if self.state.is_allowlisted(domain):
      return self._forward(request)

    if self.state.is_blocked(domain):
      src = self.state.explain_source(domain)
      # optional redirect mode (warning: HTTPS cert mismatch)
      if self.state.redirect_blocked_to_localhost and qtype in ("A","AAAA"):
        reply = request.reply()
        if qtype == "A":
          reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=30, rdata=A("127.0.0.1")))
        else:
          reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.AAAA, rclass=1, ttl=30, rdata=AAAA("::1")))
        self.state.bump(domain, qtype, src, mode="redirect_localhost")
        return reply

      reply = request.reply()
      reply.header.rcode = RCODE.NXDOMAIN
      self.state.bump(domain, qtype, src, mode="nxdomain")
      return reply

    return self._forward(request)

  def _forward(self, request):
    try:
      ip, port = self.state.upstream
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.settimeout(2.5)
      sock.sendto(request.pack(), (ip, port))
      data, _ = sock.recvfrom(4096)
      return DNSRecord.parse(data)
    except Exception:
      reply = request.reply()
      reply.header.rcode = RCODE.SERVFAIL
      return reply

class AppState:
  def __init__(self):
    self.lock = threading.Lock()

    # Core toggles
    self.enabled = {"phishing": True, "ads": True, "tracking": True}
    self.use_custom = True
    self.block_shorten = False
    self.enable_expand = False
    self.clipboard_scan = True
    self.notify_high = True
    self.auto_start_protection = False
    self.auto_enable_system_dns = False
    self.auto_revert_on_exit = True
    self.watchdog_revert = True

    # Endpoint add-ons (basic)
    self.download_shield = False
    self.quarantine_risky = True
    self.scan_with_defender = True
    self.downloads_path = ""   # empty = auto

    # New features
    self.redirect_blocked_to_localhost = False
    self.safe_mode = False
    self.temp_allow: Dict[str,str] = {}  # domain -> expiry iso
    self.remote_list_url = ""
    self.last_remote_fetch = ""

    # Team policy sync
    self.policy_url = ""
    self.policy_enabled = False
    self.policy_interval_min = 15
    self.last_policy_fetch = ""

    # New domain alert
    self.new_domain_alert = True
    self.new_domain_threshold = 30
    self.new_domain_window_sec = 60
    self._seen: Dict[str,List[float]] = {}  # domain -> timestamps

    self.upstream = DEFAULT_UPSTREAM

    self.blocked: Set[str] = set()
    self.allow: Set[str] = set()
    self.domain_source: Dict[str,str] = {}  # domain -> source label

    self.server: Optional[DNSServer] = None
    self.running = False

    self.stats = {
      "blocked_count":0, "allow_count":0,
      "hits_total":0, "last_blocked":"", "last_blocked_ts":"",
      "last_block_source":"", "last_block_mode":""
    }

  def load_config(self):
    ensure_dirs()
    if not os.path.exists(CONFIG_PATH):
      self.save_config()
      return
    try:
      with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        c = json.load(f) or {}
      for k,v in c.items():
        if hasattr(self, k):
          setattr(self, k, v)
      # sanitize / types
      self.remote_list_url = (self.remote_list_url or "").strip()
      self.policy_url = (self.policy_url or "").strip()
      if isinstance(self.upstream, list) and len(self.upstream)==2:
        self.upstream = (self.upstream[0], int(self.upstream[1]))
      if not isinstance(self.temp_allow, dict):
        self.temp_allow = {}
    except Exception:
      pass

  def save_config(self):
    ensure_dirs()
    c = {
      "enabled": self.enabled,
      "use_custom": self.use_custom,
      "block_shorten": self.block_shorten,
      "enable_expand": self.enable_expand,
      "clipboard_scan": self.clipboard_scan,
      "notify_high": self.notify_high,
      "auto_start_protection": self.auto_start_protection,
      "auto_enable_system_dns": self.auto_enable_system_dns,
      "auto_revert_on_exit": self.auto_revert_on_exit,
      "watchdog_revert": self.watchdog_revert,
      "download_shield": self.download_shield,
      "quarantine_risky": self.quarantine_risky,
      "scan_with_defender": self.scan_with_defender,
      "downloads_path": self.downloads_path,
      "redirect_blocked_to_localhost": self.redirect_blocked_to_localhost,
      "safe_mode": self.safe_mode,
      "temp_allow": self.temp_allow,
      "remote_list_url": self.remote_list_url,
      "last_remote_fetch": self.last_remote_fetch,
      "policy_url": self.policy_url,
      "policy_enabled": self.policy_enabled,
      "policy_interval_min": self.policy_interval_min,
      "last_policy_fetch": self.last_policy_fetch,
      "new_domain_alert": self.new_domain_alert,
      "new_domain_threshold": self.new_domain_threshold,
      "new_domain_window_sec": self.new_domain_window_sec,
      "upstream": list(self.upstream),
    }
    try:
      with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=2)
    except Exception:
      pass

  def apply_safe_mode(self, on: bool):
    # One-button stricter setup
    self.safe_mode = bool(on)
    if on:
      self.block_shorten = True
      self.clipboard_scan = True
      self.notify_high = True
      self.new_domain_alert = True
      # redirect mode remains OFF by default (HTTPS breaks)
      self.redirect_blocked_to_localhost = False
    self.save_config()

  def cleanup_temp_allow(self):
    now = datetime.datetime.now(datetime.timezone.utc)
    changed=False
    for d, exp in list(self.temp_allow.items()):
      dt = parse_utc_iso(exp)
      if not dt or dt <= now:
        self.temp_allow.pop(d, None)
        changed=True
    if changed:
      self.save_config()

  def allow_temporarily(self, domain: str, seconds: int):
    domain = normalize_domain(domain)
    if not domain:
      return
    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)
    self.temp_allow[domain] = exp.replace(microsecond=0).isoformat().replace("+00:00","Z")
    self.save_config()
    log_event({"type":"temp_allow_add","domain":domain,"expires":self.temp_allow[domain]})

  def is_temp_allowed(self, domain: str) -> bool:
    self.cleanup_temp_allow()
    domain = normalize_domain(domain)
    if not domain:
      return False
    # exact or parent
    if domain in self.temp_allow:
      return True
    parts = domain.split(".")
    for i in range(1, len(parts)):
      if ".".join(parts[i:]) in self.temp_allow:
        return True
    return False

  def fetch_remote_blocklist(self) -> Set[str]:
    url = (self.remote_list_url or "").strip()
    if not url:
      return set()
    txt = download_text(url, timeout=10)
    if txt is None:
      return set()
    self.last_remote_fetch = utc_iso()
    self.save_config()
    log_event({"type":"remote_blocklist_fetch","url":url,"bytes":len(txt)})
    return parse_remote_blocklist(txt)

  def fetch_policy(self) -> Optional[dict]:
    if not self.policy_enabled:
      return None
    url = (self.policy_url or "").strip()
    if not url:
      return None
    try:
      r = requests.get(url, timeout=10, headers={"User-Agent": f"BaitBusterDesktopProPlus/{APP_VERSION}"})
      if r.status_code != 200:
        return None
      j = r.json()
      if isinstance(j, dict):
        self.last_policy_fetch = utc_iso()
        self.save_config()
        log_event({"type":"policy_fetch","url":url})
        return j
    except Exception:
      return None
    return None

  def apply_policy(self, pol: dict):
    # Policy schema:
    # { "blocklist": ["bad.com"], "allowlist": ["good.com"], "safe_mode": true, "block_shorten": true, "threshold": 40 }
    try:
      bl = pol.get("blocklist") or []
      al = pol.get("allowlist") or []
      if isinstance(bl, list):
        with open(CUSTOM_BLOCKLIST_PATH, "a", encoding="utf-8") as f:
          for d in bl:
            d = normalize_domain(str(d))
            if d and DOMAIN_RE.match(d):
              f.write(d + "\n")
      if isinstance(al, list):
        with open(ALLOWLIST_PATH, "a", encoding="utf-8") as f:
          for d in al:
            d = normalize_domain(str(d))
            if d and DOMAIN_RE.match(d):
              f.write(d + "\n")
      if "safe_mode" in pol:
        self.apply_safe_mode(bool(pol.get("safe_mode")))
      if "block_shorten" in pol:
        self.block_shorten = bool(pol.get("block_shorten"))
      if "new_domain_threshold" in pol:
        try: self.new_domain_threshold = int(pol.get("new_domain_threshold"))
        except Exception: pass
      if "new_domain_window_sec" in pol:
        try: self.new_domain_window_sec = int(pol.get("new_domain_window_sec"))
        except Exception: pass
      self.save_config()
      log_event({"type":"policy_apply"})
    except Exception:
      pass

  def reload_lists(self):
    ensure_dirs()
    blocked=set()
    source_map={}
    # built-in
    for cat, urls in BLOCKLIST_SOURCES.items():
      if not self.enabled.get(cat, True):
        continue
      for u in urls:
        txt = download_text(u)
        if txt is None:
          try:
            with open(cache_path_for(u), "r", encoding="utf-8") as f:
              txt = f.read()
          except Exception:
            txt = ""
        else:
          try:
            with open(cache_path_for(u), "w", encoding="utf-8") as f:
              f.write(txt)
          except Exception:
            pass
        for line in (txt or "").splitlines():
          d = extract_domain_line(line)
          if d:
            blocked.add(d)
            source_map.setdefault(d, cat)

    # custom
    if self.use_custom:
      for d in read_domain_file(CUSTOM_BLOCKLIST_PATH):
        blocked.add(d)
        source_map.setdefault(d, "custom")

    # remote list
    for d in self.fetch_remote_blocklist():
      blocked.add(d)
      source_map.setdefault(d, "remote")

    # optional shorteners
    if self.block_shorten:
      for d in SHORTENERS:
        blocked.add(d)
        source_map.setdefault(d, "shortener")

    allow = read_domain_file(ALLOWLIST_PATH)

    with self.lock:
      self.blocked = blocked
      self.allow = allow
      self.domain_source = source_map
      self.stats["blocked_count"] = len(blocked)
      self.stats["allow_count"] = len(allow)
    log_event({"type":"reload","blocked":len(blocked),"allow":len(allow),"shorteners_blocked":self.block_shorten})

  def explain_source(self, domain: str) -> str:
    domain = normalize_domain(domain)
    with self.lock:
      src = self.domain_source.get(domain)
      if src:
        return src
    # parent lookup
    parts = domain.split(".")
    with self.lock:
      for i in range(1, len(parts)):
        p = ".".join(parts[i:])
        if p in self.domain_source:
          return self.domain_source[p]
    return "blocklist"

  def is_allowlisted(self, domain: str) -> bool:
    domain = normalize_domain(domain)
    if not domain: return False
    if self.is_temp_allowed(domain):
      return True
    with self.lock:
      if domain in self.allow: return True
      parts = domain.split(".")
      for i in range(1, len(parts)):
        if ".".join(parts[i:]) in self.allow:
          return True
    return False

  def is_blocked(self, domain: str) -> bool:
    domain = normalize_domain(domain)
    if not domain: return False
    if self.is_allowlisted(domain):
      return False
    with self.lock:
      if domain in self.blocked: return True
      parts = domain.split(".")
      for i in range(1, len(parts)):
        if ".".join(parts[i:]) in self.blocked:
          return True
    return False

  def bump(self, domain: str, qtype: str, source: str, mode: str):
    with self.lock:
      self.stats["hits_total"] += 1
      self.stats["last_blocked"] = domain
      self.stats["last_blocked_ts"] = utc_iso()
      self.stats["last_block_source"] = source
      self.stats["last_block_mode"] = mode
    log_event({"type":"dns_block","domain":domain,"qtype":qtype,"source":source,"mode":mode})

  def observe(self, domain: str):
    if not self.new_domain_alert:
      return
    domain = normalize_domain(domain)
    if not domain or domain in ("localhost",):
      return
    if DOMAIN_RE.match(domain) is None:
      return
    # ignore known allow/blocked
    if self.is_allowlisted(domain) or self.is_blocked(domain):
      return
    now = time.time()
    win = max(10, int(self.new_domain_window_sec))
    with self.lock:
      lst = self._seen.get(domain) or []
      lst = [t for t in lst if (now - t) <= win]
      lst.append(now)
      self._seen[domain] = lst
      cnt = len(lst)
    if cnt == int(self.new_domain_threshold):
      log_event({"type":"new_domain_alert","domain":domain,"count":cnt,"window_sec":win})

  def start_dns(self) -> Tuple[bool,str]:
    if self.running:
      return True, "Already running."
    try:
      resolver = FilterResolver(self)
      srv = DNSServer(resolver, port=DNS_BIND_PORT, address=DNS_BIND_IP, tcp=False)
      srv.start_thread()
      self.server = srv
      self.running = True
      log_event({"type":"dns_start","bind":f"{DNS_BIND_IP}:{DNS_BIND_PORT}","upstream":f"{self.upstream[0]}:{self.upstream[1]}"})
      return True, f"Started on {DNS_BIND_IP}:{DNS_BIND_PORT}"
    except PermissionError:
      return False, "Permission denied. Run as Administrator to bind port 53."
    except OSError as e:
      return False, f"OS error: {e}"
    except Exception as e:
      return False, f"Failed: {e}"

  def stop_dns(self) -> Tuple[bool,str]:
    if not self.running:
      return True, "Not running."
    try:
      if self.server:
        self.server.stop()
      self.server = None
      self.running = False
      log_event({"type":"dns_stop"})
      return True, "Stopped."
    except Exception as e:
      return False, f"Stop failed: {e}"

# --- Hygiene checks (best-effort) ---
def win_defender_status() -> Dict[str,str]:
  ps = r'powershell -NoProfile -ExecutionPolicy Bypass -Command "Try { $s=Get-MpComputerStatus; $o=@{RealTime=$s.RealTimeProtectionEnabled; AV=$s.AntivirusEnabled; SigAge=$s.AntispywareSignatureAge; }; $o|ConvertTo-Json -Compress } Catch { \"{}\" }"'
  code, out = run_cmd(ps)
  try:
    j = json.loads(out.strip() or "{}")
    return {k:str(v) for k,v in j.items()} if isinstance(j, dict) else {}
  except Exception:
    return {}

def win_firewall_status() -> Dict[str,str]:
  code, out = run_cmd("netsh advfirewall show allprofiles")
  if code != 0:
    return {}
  st={}
  current=None
  for ln in out.splitlines():
    if "Profile Settings" in ln:
      current = ln.strip().split(" ")[0]
    if current and "State" in ln and ":" in ln:
      st[current]=ln.split(":")[-1].strip()
  return st

# --- UI theme ---
class C:
  BG = "#0b1220"
  CARD = "#0f1a2e"
  CARD2 = "#0c1527"
  TXT = "#e7f6ff"
  MUTED = "#9fb4c7"
  ACC = "#20d2be"
  WARN = "#ffbe3d"
  BAD = "#ff5c7a"
  OK = "#35e49b"
  LINE = "#1c2a45"

def make_banner_image(w=1400,h=190):
  img=Image.new("RGBA",(w,h),(10,14,22,255))
  d=ImageDraw.Draw(img)
  for i in range(0,w,18):
    d.line([(i,0),(i-160,h)], fill=(32,210,190,40), width=2)
  for r in (160,120,80,40):
    d.ellipse([w-240-r,30-r,w-240+r,30+r], outline=(32,210,190,70), width=2)
  for x in range(0,w,90):
    for y in range(0,h,78):
      d.polygon([(x+30,y+10),(x+60,y+25),(x+60,y+55),(x+30,y+70),(x,y+55),(x,y+25)],
                outline=(120,140,170,35))
  try:
    font = ImageFont.truetype("arial.ttf", 44)
    font2 = ImageFont.truetype("arial.ttf", 18)
  except Exception:
    font = None
    font2 = None
  d.text((28,26), "BaitBuster", fill=(230,255,250,255), font=font)
  d.text((32,86), "Background phishing + malicious-domain blocking", fill=(180,255,245,220), font=font2)
  d.text((32,114), "DNS filter • URL scoring • Temp allow • Policy sync • Reports", fill=(170,210,255,180), font=font2)
  return img

class FloatingBadge:
  def __init__(self, root, on_click):
    self.root = root
    self.on_click = on_click
    self.win = tk.Toplevel(root)
    self.win.overrideredirect(True)
    self.win.attributes("-topmost", True)
    self.win.configure(bg=C.CARD2)
    self.win.geometry("170x52+30+30")
    self.win.withdraw()

    self.dot = tk.Label(self.win, text="●", bg=C.CARD2, fg=C.MUTED, font=("Segoe UI", 12, "bold"))
    self.dot.pack(side="left", padx=(10,6), pady=10)
    self.lbl = tk.Label(self.win, text="Not protected", bg=C.CARD2, fg=C.TXT, font=("Segoe UI", 10, "bold"))
    self.lbl.pack(side="left", pady=10)

    for w in (self.win, self.dot, self.lbl):
      w.bind("<Button-1>", lambda e: self.on_click())

  def show(self):
    self.win.deiconify()

  def hide(self):
    self.win.withdraw()

  def set_status(self, protected: bool, warn: bool=False):
    if protected:
      self.dot.config(fg=C.OK)
      self.lbl.config(text="Protected")
    else:
      self.dot.config(fg=C.WARN if warn else C.MUTED)
      self.lbl.config(text="Not protected")

class UI:
  def __init__(self, state: AppState):
    self.state=state
    ensure_dirs()
    self.state.load_config()
    self.state.reload_lists()

    self.root=tk.Tk()
    self.root.title(f"{APP_NAME} v{APP_VERSION}")
    self.root.geometry("1040x700")
    self.root.minsize(980, 660)
    self.root.configure(bg=C.BG)

    self.msg_q=queue.Queue()
    self._clipboard_last=""
    self._tray=None
    self._banner_photo=None
    self._badge=None

    self._setup_ttk()
    self._build()
    self._start_tray()

    self.root.after(800, self._tick)
    self.root.after(900, self._poll_clipboard)
    threading.Thread(target=self._watchdog_loop, daemon=True).start()
    threading.Thread(target=self._policy_loop, daemon=True).start()
    threading.Thread(target=self._download_shield_loop, daemon=True).start()
    threading.Thread(target=self._new_domain_notify_loop, daemon=True).start()

    self.root.protocol("WM_DELETE_WINDOW", self._hide_to_tray)
    self.root.after(500, self._auto_start_if_enabled)
    self.root.after(800, self._startup_safety_check)

  def _setup_ttk(self):
    s=ttk.Style(self.root)
    try: s.theme_use("clam")
    except Exception: pass
    s.configure(".", background=C.BG, foreground=C.TXT, fieldbackground=C.CARD, bordercolor=C.LINE)
    s.configure("TFrame", background=C.BG)
    s.configure("Card.TFrame", background=C.CARD)
    s.configure("Card2.TFrame", background=C.CARD2)
    s.configure("TLabel", background=C.BG, foreground=C.TXT)
    s.configure("Card.TLabel", background=C.CARD, foreground=C.TXT)
    s.configure("TButton", background=C.CARD, foreground=C.TXT, borderwidth=0, padding=(12,7))
    s.map("TButton", background=[("active","#12203a")])
    s.configure("Accent.TButton", background=C.ACC, foreground="#07221f", padding=(12,7))
    s.map("Accent.TButton", background=[("active","#31e6d2")])
    s.configure("Warn.TButton", background=C.WARN, foreground="#1e1300")
    s.configure("Bad.TButton", background=C.BAD, foreground="#210008")
    s.configure("OK.TButton", background=C.OK, foreground="#062014")
    s.configure("TNotebook", background=C.BG, borderwidth=0)
    s.configure("TNotebook.Tab", background=C.CARD2, foreground=C.TXT, padding=(12,8))
    s.map("TNotebook.Tab", background=[("selected",C.CARD)])
    s.configure("TEntry", padding=6, relief="flat")
    s.configure("Treeview", background=C.CARD, fieldbackground=C.CARD, foreground=C.TXT, rowheight=26, bordercolor=C.LINE)
    s.configure("Treeview.Heading", background=C.CARD2, foreground=C.TXT)

  def _build(self):
    outer=ttk.Frame(self.root); outer.pack(fill="both", expand=True)

    # banner
    bf=ttk.Frame(outer, style="Card2.TFrame"); bf.pack(fill="x")
    img=make_banner_image(1600,190)
    self._banner_photo=ImageTk.PhotoImage(img)
    cv=tk.Canvas(bf, height=190, bg=C.BG, highlightthickness=0)
    cv.pack(fill="x")
    cv.create_image(0,0, anchor="nw", image=self._banner_photo)

    # status bar
    bar=ttk.Frame(outer, style="Card.TFrame"); bar.pack(fill="x")
    self.dot=tk.Label(bar, text="●", bg=C.CARD, fg=C.OK, font=("Segoe UI", 13, "bold"))
    self.dot.pack(side="left", padx=(14,6), pady=10)
    self.status=tk.Label(bar, text="Ready", bg=C.CARD, fg=C.TXT, font=("Segoe UI", 11, "bold"))
    self.status.pack(side="left", pady=10)
    self.quick=tk.Label(bar, text="", bg=C.CARD, fg=C.MUTED)
    self.quick.pack(side="left", padx=(16,0), pady=10)

    ttk.Button(bar, text="Safe Mode", command=self.toggle_safe_mode, style="Warn.TButton").pack(side="right", padx=10, pady=8)
    ttk.Button(bar, text="Reload Lists", command=self.reload_lists).pack(side="right", padx=(0,10), pady=8)
    ttk.Button(bar, text="Quit", command=self.quit_app, style="Bad.TButton").pack(side="right", padx=(0,10), pady=8)

    # notebook
    body=ttk.Frame(outer); body.pack(fill="both", expand=True, padx=12, pady=12)
    self.nb=ttk.Notebook(body); self.nb.pack(fill="both", expand=True)

    self.tab_protect=ttk.Frame(self.nb)
    self._make_tab_scrollable(self.tab_protect, "tab_protect")
    self.tab_scan=ttk.Frame(self.nb)
    self.tab_policy=ttk.Frame(self.nb)
    self.tab_hyg=ttk.Frame(self.nb)
    self.tab_reports=ttk.Frame(self.nb)
    self.tab_logs=ttk.Frame(self.nb)

    self.nb.add(self.tab_protect, text="Protection")
    self.nb.add(self.tab_scan, text="Scanner")
    self.nb.add(self.tab_policy, text="Policies")
    self.nb.add(self.tab_hyg, text="Hygiene")
    self.nb.add(self.tab_reports, text="Reports")
    self.nb.add(self.tab_logs, text="Logs")

    self._build_protection()
    self._build_scanner()
    self._build_policies()
    self._build_reports()
    self._build_hygiene()
    self._build_logs()

  def _make_tab_scrollable(self, tab, prefix: str):
    # Makes a Notebook tab scrollable vertically (for smaller screens).
    canvas = tk.Canvas(tab, bg=C.BG, highlightthickness=0, bd=0)
    vscroll = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vscroll.set)

    vscroll.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    inner = ttk.Frame(canvas)
    win = canvas.create_window((0, 0), window=inner, anchor="nw")

    def _on_inner_config(_e=None):
      canvas.configure(scrollregion=canvas.bbox("all"))
    inner.bind("<Configure>", _on_inner_config)

    def _on_canvas_config(e):
      canvas.itemconfigure(win, width=e.width)
    canvas.bind("<Configure>", _on_canvas_config)

    def _on_wheel(ev):
      if getattr(ev, "delta", 0):
        canvas.yview_scroll(int(-1 * (ev.delta / 120)), "units")

    def _enter(_e=None):
      canvas.bind_all("<MouseWheel>", _on_wheel)

    def _leave(_e=None):
      canvas.unbind_all("<MouseWheel>")

    canvas.bind("<Enter>", _enter)
    canvas.bind("<Leave>", _leave)

    setattr(self, f"{prefix}_content", inner)
    setattr(self, f"{prefix}_canvas", canvas)
    setattr(self, f"{prefix}_vscroll", vscroll)

  def _card(self, parent, title, sub=""):
    c=ttk.Frame(parent, style="Card.TFrame"); c.pack(fill="x", pady=8)
    h=ttk.Frame(c, style="Card.TFrame"); h.pack(fill="x", padx=14, pady=(12,6))
    tk.Label(h, text=title, bg=C.CARD, fg=C.TXT, font=("Segoe UI", 12, "bold")).pack(anchor="w")
    if sub:
      tk.Label(h, text=sub, bg=C.CARD, fg=C.MUTED).pack(anchor="w", pady=(2,0))
    return c

  # ------------------ Tabs ------------------
  def _build_protection(self):
    parent=getattr(self, 'tab_protect_content', self.tab_protect)
    left=ttk.Frame(parent); left.pack(side="left", fill="both", expand=True, padx=(12,6), pady=12)
    right=ttk.Frame(parent); right.pack(side="right", fill="both", expand=True, padx=(6,12), pady=12)

    dns=self._card(left, "DNS Background Protection", "Blocks phishing/ads/tracking domains for all browsers/apps.")
    self.dns_lbl=tk.Label(dns, text="DNS Filter: Stopped", bg=C.CARD, fg=C.MUTED, font=("Segoe UI", 11, "bold"))
    self.dns_lbl.pack(anchor="w", padx=14, pady=(0,10))

    b=ttk.Frame(dns, style="Card.TFrame"); b.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(b, text="Start DNS Filter", command=self.start_dns, style="Accent.TButton").pack(side="left")
    ttk.Button(b, text="Stop", command=self.stop_dns).pack(side="left", padx=(8,0))
    ttk.Button(b, text="Fix Internet Now", command=self.fix_internet_now, style="Warn.TButton").pack(side="left", padx=(8,0))

    sysc=self._card(left, "Apply to This PC (Windows)", "Sets Windows DNS to 127.0.0.1 so filtering applies system-wide.")
    self.iface=tk.Label(sysc, text="Interface: (detecting…)", bg=C.CARD, fg=C.MUTED)
    self.iface.pack(anchor="w", padx=14, pady=(0,6))
    sb=ttk.Frame(sysc, style="Card.TFrame"); sb.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(sb, text="Enable System DNS", command=self.enable_system_dns, style="OK.TButton").pack(side="left")
    ttk.Button(sb, text="Disable (Revert)", command=self.disable_system_dns).pack(side="left", padx=(8,0))

    stats=self._card(left, "Live Stats", "What your DNS filter has blocked so far.")
    self.stats=tk.Text(stats, height=8, bg=C.CARD, fg=C.TXT, insertbackground=C.TXT, relief="flat")
    self.stats.pack(fill="x", padx=14, pady=(0,12))
    self.stats.configure(state="disabled")

    togg=self._card(right, "Controls", "Safety features prevent the DNS-stuck issue after reboot/shutdown.")
    g=ttk.Frame(togg, style="Card.TFrame"); g.pack(fill="x", padx=14, pady=(0,12))

    self.v_clip=tk.BooleanVar(value=bool(self.state.clipboard_scan))
    self.v_notify=tk.BooleanVar(value=bool(self.state.notify_high))
    self.v_auto=tk.BooleanVar(value=bool(self.state.auto_start_protection))
    self.v_autodns=tk.BooleanVar(value=bool(self.state.auto_enable_system_dns))
    self.v_revert=tk.BooleanVar(value=bool(self.state.auto_revert_on_exit))
    self.v_watch=tk.BooleanVar(value=bool(self.state.watchdog_revert))
    self.v_short=tk.BooleanVar(value=bool(self.state.block_shorten))
    self.v_expand=tk.BooleanVar(value=bool(self.state.enable_expand))
    self.v_redirect=tk.BooleanVar(value=bool(self.state.redirect_blocked_to_localhost))
    self.v_newdom=tk.BooleanVar(value=bool(self.state.new_domain_alert))
    self.v_badge=tk.BooleanVar(value=False)
    self.v_dshield=tk.BooleanVar(value=bool(self.state.download_shield))
    self.v_quar=tk.BooleanVar(value=bool(self.state.quarantine_risky))
    self.v_def=tk.BooleanVar(value=bool(self.state.scan_with_defender))

    def add(row, text, var):
      ttk.Checkbutton(g, text=text, variable=var, command=self.apply_settings).grid(row=row, column=0, sticky="w", pady=4)

    add(0, "Clipboard auto-scan (copied URLs)", self.v_clip)
    add(1, "Notify on HIGH/CRITICAL", self.v_notify)
    add(2, "Auto-start DNS filter on launch", self.v_auto)
    add(3, "Auto-enable System DNS on launch (Windows)", self.v_autodns)
    add(4, "Auto-revert System DNS on exit", self.v_revert)
    add(5, "Watchdog: revert if DNS=localhost but filter OFF", self.v_watch)
    add(6, "Block URL shorteners at DNS level", self.v_short)
    add(7, "Expand shorteners during scans", self.v_expand)
    add(8, "Redirect blocked A/AAAA to localhost (HTTPS may break)", self.v_redirect)
    add(9, "New-domain spike alerts", self.v_newdom)
    add(10,"Floating status badge", self.v_badge)
    add(11,"Download/attachment shield (Downloads folder)", self.v_dshield)
    add(12,"Quarantine risky downloads (exe/scripts/macros)", self.v_quar)
    add(13,"Scan quarantined files with Windows Defender", self.v_def)

    diag=self._card(right, "Diagnostics", "Quick checks.")
    db=ttk.Frame(diag, style="Card.TFrame"); db.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(db, text="Test DNS (nslookup)", command=self.test_dns).pack(side="left")
    ttk.Button(db, text="Open Logs Folder", command=self.open_logs_folder).pack(side="left", padx=(8,0))
    ttk.Button(db, text="Jump to Logs", command=lambda: self.nb.select(self.tab_logs)).pack(side="left", padx=(8,0))

    dl=self._card(right, "Download Shield", "Watches your Downloads folder; quarantines risky files and scans with Defender.")
    self.dl_lbl=tk.Label(dl, text="Download Shield: Stopped", bg=C.CARD, fg=C.MUTED, font=("Segoe UI", 11, "bold"))
    self.dl_lbl.pack(anchor="w", padx=14, pady=(0,10))
    bb=ttk.Frame(dl, style="Card.TFrame"); bb.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(bb, text="Start Download Shield", command=self.start_download_shield, style="Accent.TButton").pack(side="left")
    ttk.Button(bb, text="Stop", command=self.stop_download_shield).pack(side="left", padx=(8,0))
    ttk.Button(bb, text="Open Quarantine", command=self.open_quarantine_folder).pack(side="left", padx=(8,0))
    ttk.Button(bb, text="Scan a File…", command=self.scan_file_dialog).pack(side="left", padx=(8,0))

  def _build_scanner(self):
    wrap=ttk.Frame(self.tab_scan); wrap.pack(fill="both", expand=True, padx=12, pady=12)
    c=self._card(wrap, "Suspicious Link Scanner", "Paste a URL (or decode from QR) to get a verdict + reasons.")
    top=ttk.Frame(c, style="Card.TFrame"); top.pack(fill="x", padx=14, pady=(0,10))
    tk.Label(top, text="URL:", bg=C.CARD, fg=C.TXT).pack(side="left")
    self.url=ttk.Entry(top); self.url.pack(side="left", padx=(8,8), fill="x", expand=True)
    ttk.Button(top, text="Scan", command=self.scan_url, style="Accent.TButton").pack(side="left")
    ttk.Button(top, text="QR Image…", command=self.scan_qr_image).pack(side="left", padx=(8,0))
    ttk.Button(top, text="Clear", command=lambda: self.url.delete(0,"end")).pack(side="left", padx=(8,0))

    self.out=tk.Text(c, bg=C.CARD, fg=C.TXT, insertbackground=C.TXT, relief="flat")
    self.out.pack(fill="both", expand=True, padx=14, pady=(0,12))

  def _build_policies(self):
    wrap=ttk.Frame(self.tab_policy); wrap.pack(fill="both", expand=True, padx=12, pady=12)

    lists=self._card(wrap, "Lists", "Allowlist always wins. Blocklists add extra domains.")
    row=ttk.Frame(lists, style="Card.TFrame"); row.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(row, text="Open Allowlist", command=lambda: self.open_file(ALLOWLIST_PATH)).pack(side="left")
    ttk.Button(row, text="Open Custom Blocklist", command=lambda: self.open_file(CUSTOM_BLOCKLIST_PATH)).pack(side="left", padx=(8,0))
    ttk.Button(row, text="Reload Now", command=self.reload_lists, style="Accent.TButton").pack(side="left", padx=(8,0))

    temp=self._card(wrap, "Temporary Allow (auto-expires)", "Fix broken sites temporarily without weakening security permanently.")
    tr=ttk.Frame(temp, style="Card.TFrame"); tr.pack(fill="x", padx=14, pady=(0,10))
    tk.Label(tr, text="Domain:", bg=C.CARD, fg=C.TXT).pack(side="left")
    self.temp_domain=ttk.Entry(tr, width=30); self.temp_domain.pack(side="left", padx=(8,10))
    tk.Label(tr, text="Duration:", bg=C.CARD, fg=C.TXT).pack(side="left")
    self.temp_dur=ttk.Combobox(tr, values=["15 minutes","1 hour","1 day"], width=12, state="readonly")
    self.temp_dur.current(1)
    self.temp_dur.pack(side="left", padx=(8,10))
    ttk.Button(tr, text="Add", command=self.add_temp_allow, style="OK.TButton").pack(side="left")

    self.temp_tree = ttk.Treeview(temp, columns=("domain","expires"), show="headings", height=6)
    self.temp_tree.heading("domain", text="Domain")
    self.temp_tree.heading("expires", text="Expires (UTC)")
    self.temp_tree.column("domain", width=360)
    self.temp_tree.column("expires", width=220)
    self.temp_tree.pack(fill="x", padx=14, pady=(0,10))
    btn=ttk.Frame(temp, style="Card.TFrame"); btn.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(btn, text="Remove Selected", command=self.remove_temp_allow).pack(side="left")
    ttk.Button(btn, text="Refresh", command=self.refresh_temp_allows).pack(side="left", padx=(8,0))

    remote=self._card(wrap, "Remote Blocklist URL", "Optional plain-text list: one domain per line.")
    rr=ttk.Frame(remote, style="Card.TFrame"); rr.pack(fill="x", padx=14, pady=(0,10))
    tk.Label(rr, text="URL:", bg=C.CARD, fg=C.TXT).pack(side="left")
    self.remote=ttk.Entry(rr); self.remote.pack(side="left", padx=(8,8), fill="x", expand=True)
    self.remote.insert(0, self.state.remote_list_url or "")
    ttk.Button(rr, text="Save", command=self.save_remote_url, style="Accent.TButton").pack(side="left")
    self.remote_status=tk.Label(remote, text="Last fetch: (none)", bg=C.CARD, fg=C.MUTED)
    self.remote_status.pack(anchor="w", padx=14, pady=(0,12))

    pol=self._card(wrap, "Team Policy Sync (policy.json)", "Control settings + lists via a shared JSON URL.")
    pr=ttk.Frame(pol, style="Card.TFrame"); pr.pack(fill="x", padx=14, pady=(0,10))
    self.v_pol=tk.BooleanVar(value=bool(self.state.policy_enabled))
    ttk.Checkbutton(pr, text="Enable policy sync", variable=self.v_pol, command=self.apply_settings).pack(side="left")
    tk.Label(pr, text="URL:", bg=C.CARD, fg=C.TXT).pack(side="left", padx=(10,0))
    self.policy=ttk.Entry(pr); self.policy.pack(side="left", padx=(8,8), fill="x", expand=True)
    self.policy.insert(0, self.state.policy_url or "")
    ttk.Button(pr, text="Sync Now", command=self.sync_policy_now, style="Accent.TButton").pack(side="left")

    pr2=ttk.Frame(pol, style="Card.TFrame"); pr2.pack(fill="x", padx=14, pady=(0,12))
    tk.Label(pr2, text="Interval (min):", bg=C.CARD, fg=C.TXT).pack(side="left")
    self.policy_int=ttk.Entry(pr2, width=6); self.policy_int.pack(side="left", padx=(8,12))
    self.policy_int.insert(0, str(self.state.policy_interval_min))
    ttk.Button(pr2, text="Save", command=self.save_policy_settings).pack(side="left")
    self.policy_status=tk.Label(pol, text="Last policy fetch: (none)", bg=C.CARD, fg=C.MUTED)
    self.policy_status.pack(anchor="w", padx=14, pady=(0,12))

  def _build_hygiene(self):
    wrap=ttk.Frame(self.tab_hyg); wrap.pack(fill="both", expand=True, padx=12, pady=12)
    c=self._card(wrap, "Endpoint Hygiene Checks (best-effort)", "Helps reduce malware risk (including keyloggers).")
    self.hyg=tk.Text(c, bg=C.CARD, fg=C.TXT, insertbackground=C.TXT, relief="flat", height=18)
    self.hyg.pack(fill="both", expand=True, padx=14, pady=(0,10))
    b=ttk.Frame(c, style="Card.TFrame"); b.pack(fill="x", padx=14, pady=(0,12))
    ttk.Button(b, text="Run Checks", command=self.run_hygiene, style="Accent.TButton").pack(side="left")
    ttk.Button(b, text="Open Startup Folder", command=self.open_startup_folder).pack(side="left", padx=(8,0))
    self.run_hygiene()

  def _build_reports(self):
    wrap=ttk.Frame(self.tab_reports); wrap.pack(fill="both", expand=True, padx=12, pady=12)
    c=self._card(wrap, "Incident Reports", "Export a summary of blocks/scans for visibility (CSV + PDF).")
    r=ttk.Frame(c, style="Card.TFrame"); r.pack(fill="x", padx=14, pady=(0,10))
    tk.Label(r, text="Range:", bg=C.CARD, fg=C.TXT).pack(side="left")
    self.rep_range=ttk.Combobox(r, values=["Last 24 hours","Last 7 days","Last 30 days","All time"], width=14, state="readonly")
    self.rep_range.current(1)
    self.rep_range.pack(side="left", padx=(8,12))
    ttk.Button(r, text="Export CSV", command=self.export_csv, style="Accent.TButton").pack(side="left")
    ttk.Button(r, text="Export PDF", command=self.export_pdf).pack(side="left", padx=(8,0))

    self.rep_out=tk.Text(c, bg=C.CARD, fg=C.TXT, insertbackground=C.TXT, relief="flat", height=18)
    self.rep_out.pack(fill="both", expand=True, padx=14, pady=(0,12))
    self.refresh_report_preview()

  def _build_logs(self):
    wrap=ttk.Frame(self.tab_logs); wrap.pack(fill="both", expand=True, padx=12, pady=12)
    c=self._card(wrap, "Event Log (local)", "Visibility for troubleshooting: blocks, scans, policy sync, watchdog actions.")
    top=ttk.Frame(c, style="Card.TFrame"); top.pack(fill="x", padx=14, pady=(0,10))
    ttk.Button(top, text="Refresh", command=self.refresh_log_view, style="Accent.TButton").pack(side="left")
    ttk.Button(top, text="Open events.jsonl", command=self.open_events_file).pack(side="left", padx=(8,0))
    ttk.Button(top, text="Copy selected line", command=self.copy_selected_log).pack(side="left", padx=(8,0))

    self.log_view = tk.Text(c, bg=C.CARD, fg=C.TXT, insertbackground=C.TXT, relief="flat")
    self.log_view.pack(fill="both", expand=True, padx=14, pady=(0,12))
    self.refresh_log_view()

  # ------------------ Actions ------------------
  def apply_settings(self):
    self.state.clipboard_scan=bool(self.v_clip.get())
    self.state.notify_high=bool(self.v_notify.get())
    self.state.auto_start_protection=bool(self.v_auto.get())
    self.state.auto_enable_system_dns=bool(self.v_autodns.get())
    self.state.auto_revert_on_exit=bool(self.v_revert.get())
    self.state.watchdog_revert=bool(self.v_watch.get())
    self.state.block_shorten=bool(self.v_short.get())
    self.state.enable_expand=bool(self.v_expand.get())
    self.state.redirect_blocked_to_localhost=bool(self.v_redirect.get())
    self.state.new_domain_alert=bool(self.v_newdom.get())
    self.state.download_shield=bool(self.v_dshield.get())
    self.state.quarantine_risky=bool(self.v_quar.get())
    self.state.scan_with_defender=bool(self.v_def.get())

    # badge
    show_badge = bool(self.v_badge.get())
    if show_badge and not self._badge:
      self._badge = FloatingBadge(self.root, on_click=self._show_from_tray)
      self._badge.show()
    if (not show_badge) and self._badge:
      self._badge.hide()
      self._badge = None

    # policy enable + policy url field save
    if hasattr(self, "v_pol"):
      self.state.policy_enabled = bool(self.v_pol.get())
    if hasattr(self, "policy"):
      self.state.policy_url = (self.policy.get() or "").strip()

    self.state.save_config()
    self.state.reload_lists()
    self.toast("Settings applied.", ok=True)
    self._refresh_status()

  def start_download_shield(self):
    self.state.download_shield = True
    try:
      self.v_dshield.set(True)
    except Exception:
      pass
    self.state.save_config()
    self.toast("Download Shield started.", ok=True)
    self._refresh_status()

  def stop_download_shield(self):
    self.state.download_shield = False
    try:
      self.v_dshield.set(False)
    except Exception:
      pass
    self.state.save_config()
    self.toast("Download Shield stopped.", ok=True)
    self._refresh_status()

  def open_quarantine_folder(self):
    ensure_dirs()
    try:
      if is_windows():
        os.startfile(QUAR_DIR)
      else:
        webbrowser.open(QUAR_DIR)
    except Exception:
      self.toast("Could not open quarantine folder.", ok=False)

  def scan_file_dialog(self):
    try:
      from tkinter import filedialog
      p = filedialog.askopenfilename(title="Select a file to scan")
      if not p:
        return
      ok, out = defender_scan_file(p)
      if ok:
        self.toast("Defender scan requested.", ok=True)
      else:
        self.toast("Defender scan failed / not available.", ok=False)
      log_event({"type":"defender_scan", "path":p, "ok":ok, "msg":out[:200]})
      self.refresh_log_view()
    except Exception as e:
      self.toast(f"Scan failed: {e}", ok=False)

  def _download_shield_loop(self):
    # Poll Downloads folder to avoid extra deps
    seen = {}  # path -> (size, mtime)
    while True:
      time.sleep(2.0)
      try:
        if not bool(self.state.download_shield):
          continue
        d = get_downloads_dir(self.state.downloads_path)
        if not os.path.isdir(d):
          continue
        for ent in os.scandir(d):
          try:
            if not ent.is_file():
              continue
            p = ent.path
            st = ent.stat()
            sig = (st.st_size, int(st.st_mtime))
            if seen.get(p) == sig:
              continue
            # update snapshot
            seen[p] = sig
            # skip tiny temp partials
            if p.endswith(".crdownload") or p.endswith(".tmp") or p.endswith(".part"):
              continue
            if is_risky_file(p) and bool(self.state.quarantine_risky):
              # attempt quarantine
              try:
                q = quarantine_file(p)
                log_event({"type":"download_quarantine","orig":p,"quarantine":q,"reason":"risky_extension"})
                self.state.stats["last_blocked"] = os.path.basename(p)
                self.state.stats["last_block_source"] = "download_shield"
                self.state.stats["last_block_ts"] = now_iso()
                # optional Defender scan
                if bool(self.state.scan_with_defender):
                  ok, out = defender_scan_file(q)
                  log_event({"type":"defender_scan","path":q,"ok":ok,"msg":out[:300]})
                # notify
                if bool(self.state.notify_high):
                  self.toast(f"Quarantined risky download: {os.path.basename(p)}", ok=False)
                # refresh views
                self.refresh_log_view()
                self._refresh_status()
              except Exception as e:
                log_event({"type":"download_quarantine_error","path":p,"err":str(e)})
          except Exception:
            pass
      except Exception:
        pass



  def toggle_safe_mode(self):
    # Toggle safe mode; apply stricter defaults when enabling
    self.state.apply_safe_mode(not bool(self.state.safe_mode))
    self.state.reload_lists()
    # update checkboxes
    self.v_short.set(bool(self.state.block_shorten))
    self.v_clip.set(bool(self.state.clipboard_scan))
    self.v_notify.set(bool(self.state.notify_high))
    self.v_newdom.set(bool(self.state.new_domain_alert))
    self.toast("Safe Mode enabled." if self.state.safe_mode else "Safe Mode disabled.", ok=True)
    log_event({"type":"safe_mode","enabled":self.state.safe_mode})
    self._refresh_status()

  def start_dns(self):
    ok,msg=self.state.start_dns()
    self.toast(msg, ok=ok)
    self._refresh_status()

  def stop_dns(self):
    ok,msg=self.state.stop_dns()
    self.toast(msg, ok=ok)
    self._refresh_status()

  def enable_system_dns(self):
    if not is_windows():
      messagebox.showinfo(APP_NAME, "System DNS apply is Windows-only.")
      return
    if not self.state.running:
      messagebox.showwarning(APP_NAME, "Start DNS Filter first.")
      return
    iface=win_active_iface()
    if not iface:
      messagebox.showerror(APP_NAME, "No active interface detected.")
      return
    ok,out=win_dns_set_local(iface)
    log_event({"type":"system_dns_enable","iface":iface,"ok":ok,"out":out})
    if ok:
      self.toast("System DNS enabled (127.0.0.1).", ok=True)
    else:
      messagebox.showerror(APP_NAME, out)
      self.toast("Failed enabling System DNS.", ok=False)
    self._refresh_status()

  def disable_system_dns(self):
    if not is_windows():
      messagebox.showinfo(APP_NAME, "System DNS revert is Windows-only.")
      return
    iface=win_active_iface()
    if not iface:
      messagebox.showerror(APP_NAME, "No active interface detected.")
      return
    ok,out=win_dns_reset_dhcp(iface)
    log_event({"type":"system_dns_disable","iface":iface,"ok":ok,"out":out})
    if ok:
      self.toast("System DNS reverted (DHCP).", ok=True)
    else:
      messagebox.showerror(APP_NAME, out)
      self.toast("Failed reverting DNS.", ok=False)
    self._refresh_status()

  def fix_internet_now(self):
    if not is_windows():
      messagebox.showinfo(APP_NAME, "Fix Internet Now is Windows-focused.")
      return
    iface=win_active_iface()
    if not iface:
      messagebox.showerror(APP_NAME, "No active interface detected.")
      return
    ok,out=win_dns_reset_dhcp(iface)
    log_event({"type":"fix_internet_now","iface":iface,"ok":ok,"out":out})
    if ok:
      self.toast("Internet fix applied (DNS reverted).", ok=True)
    else:
      messagebox.showerror(APP_NAME, out)
      self.toast("Internet fix failed.", ok=False)
    self._refresh_status()

  def scan_url(self):
    u=(self.url.get() or "").strip()
    with self.state.lock:
      blocked=set(self.state.blocked); allow=set(self.state.allow); ex=bool(self.state.enable_expand); explain=dict(self.state.domain_source)
    r=analyze_url(u, blocked, allow, enable_expand=ex, explain=explain)

    lines=[f"Verdict: {r.verdict}"]
    if r.verdict not in ("EMPTY","ALLOWLIST"):
      lines.append(f"Score: {r.score}/100")
    lines += ["", f"Normalized: {r.normalized}", f"Host: {r.host}"]
    if r.expanded:
      lines.append(f"Expanded: {r.expanded}")
    lines += ["", "Reasons:"]
    for rr in r.reasons:
      lines.append(f"- {rr}")

    self.out.delete("1.0","end")
    self.out.insert("1.0","\n".join(lines))

    log_event({"type":"manual_scan","input":r.input,"host":r.host,"score":r.score,"verdict":r.verdict,"reasons":r.reasons,"expanded":r.expanded})
    self.refresh_log_view()
    if hasattr(self, 'rep_range'):
      self.refresh_report_preview()

    if self.state.notify_high and r.verdict in ("HIGH","CRITICAL"):
      self.toast(f"{r.verdict}: {r.host} ({r.score}/100)", ok=False)

  def scan_qr_image(self):
    path = filedialog.askopenfilename(title="Select QR image", filetypes=[("Images","*.png;*.jpg;*.jpeg;*.bmp;*.webp"),("All","*.*")])
    if not path:
      return
    try:
      img = cv2.imread(path)
      det = cv2.QRCodeDetector()
      data, pts, _ = det.detectAndDecode(img)
      data = (data or "").strip()
      if not data:
        messagebox.showwarning(APP_NAME, "No QR code detected in that image.")
        return
      self.url.delete(0,"end")
      self.url.insert(0, data)
      log_event({"type":"qr_decode","file":os.path.basename(path),"decoded":data[:400]})
      self.scan_url()
    except Exception as e:
      messagebox.showerror(APP_NAME, f"QR scan failed:\n{e}")

  def reload_lists(self):
    self.state.reload_lists()
    self.toast("Lists reloaded.", ok=True)
    self._refresh_status()

  def save_remote_url(self):
    self.state.remote_list_url = (self.remote.get() or "").strip()
    self.state.save_config()
    self.reload_lists()
    self.toast("Remote blocklist URL saved.", ok=True)

  def save_policy_settings(self):
    self.state.policy_url = (self.policy.get() or "").strip()
    try:
      self.state.policy_interval_min = max(5, int(self.policy_int.get().strip()))
    except Exception:
      self.state.policy_interval_min = 15
    self.state.policy_enabled = bool(self.v_pol.get())
    self.state.save_config()
    self.toast("Policy settings saved.", ok=True)

  def sync_policy_now(self):
    self.save_policy_settings()
    pol = self.state.fetch_policy()
    if pol:
      self.state.apply_policy(pol)
      self.state.reload_lists()
      self.toast("Policy synced & applied.", ok=True)
      self.refresh_temp_allows()
      self._refresh_status()
    else:
      self.toast("Policy sync failed (check URL).", ok=False)

  def add_temp_allow(self):
    d = normalize_domain(self.temp_domain.get().strip())
    if not d or DOMAIN_RE.match(d) is None:
      messagebox.showerror(APP_NAME, "Please enter a valid domain (example.com).")
      return
    dur = self.temp_dur.get()
    sec = 3600
    if "15" in dur: sec = 15*60
    elif "hour" in dur: sec = 60*60
    elif "day" in dur: sec = 24*60*60
    self.state.allow_temporarily(d, sec)
    self.temp_domain.delete(0,"end")
    self.refresh_temp_allows()
    self.toast(f"Temporarily allowed: {d}", ok=True)

  def remove_temp_allow(self):
    sel = self.temp_tree.selection()
    if not sel:
      return
    for iid in sel:
      dom = self.temp_tree.item(iid, "values")[0]
      self.state.temp_allow.pop(dom, None)
      log_event({"type":"temp_allow_remove","domain":dom})
    self.state.save_config()
    self.refresh_temp_allows()
    self.toast("Removed.", ok=True)

  def refresh_temp_allows(self):
    self.state.cleanup_temp_allow()
    for i in self.temp_tree.get_children():
      self.temp_tree.delete(i)
    items = sorted(self.state.temp_allow.items(), key=lambda kv: kv[0])
    for dom, exp in items:
      self.temp_tree.insert("", "end", values=(dom, exp))

  def run_hygiene(self):
    out=[]
    out.append("Hygiene snapshot (best-effort):")
    out.append("")
    if is_windows():
      iface = win_active_iface() or "(unknown)"
      out.append(f"Active interface: {iface}")
      out.append(f"System DNS points to localhost: {windows_dns_is_pointing_localhost()}")
      d = win_defender_status()
      out.append("")
      out.append("Windows Defender:")
      if d:
        out.append(f"- Real-time: {d.get('RealTime','?')}")
        out.append(f"- Antivirus enabled: {d.get('AV','?')}")
        out.append(f"- Signature age: {d.get('SigAge','?')} days")
      else:
        out.append("- (status not accessible)")
      fw = win_firewall_status()
      out.append("")
      out.append("Firewall profiles:")
      if fw:
        for k,v in fw.items():
          out.append(f"- {k}: {v}")
      else:
        out.append("- (status not accessible)")
      out.append("")
      out.append("Practical defenses:")
      out.append("- Use passkeys/password-manager autofill to reduce typing exposure.")
      out.append("- Enable MFA on email + admin accounts.")
      out.append("- Avoid unknown browser extensions; review installed ones monthly.")
      out.append("- Keep Windows updated; reboot after patching.")
    else:
      out.append("Non-Windows OS detected. Limited checks available.")
      out.append("- Use MFA + password manager; keep OS updated.")
    self.hyg.delete("1.0","end")
    self.hyg.insert("1.0","\n".join(out))
    log_event({"type":"hygiene_run"})
    self.refresh_log_view()
    if hasattr(self, 'rep_range'):
      self.refresh_report_preview()

  def open_startup_folder(self):
    if not is_windows():
      messagebox.showinfo(APP_NAME, "Startup folder is Windows-focused.")
      return
    path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    try:
      os.startfile(path)
    except Exception:
      pass

  def open_file(self, path: str):
    ensure_dirs()
    try:
      if is_windows(): os.startfile(path)
      else: messagebox.showinfo(APP_NAME, path)
    except Exception:
      messagebox.showerror(APP_NAME, f"Could not open:\n{path}")

  def open_logs_folder(self):
    ensure_dirs()
    try:
      if is_windows(): os.startfile(LOG_DIR)
      else: messagebox.showinfo(APP_NAME, LOG_DIR)
    except Exception:
      pass

  def open_events_file(self):
    ensure_dirs()
    path = os.path.join(LOG_DIR, "events.jsonl")
    try:
      if is_windows(): os.startfile(path)
      else: messagebox.showinfo(APP_NAME, path)
    except Exception:
      pass

  def refresh_log_view(self):
    ensure_dirs()
    src = os.path.join(LOG_DIR, "events.jsonl")
    if not os.path.exists(src):
      self.log_view.delete("1.0","end")
      self.log_view.insert("1.0","(no logs yet)")
      return
    try:
      with open(src, "r", encoding="utf-8") as f:
        lines = f.readlines()[-350:]
      self.log_view.delete("1.0","end")
      self.log_view.insert("1.0","".join(lines))
    except Exception:
      pass

  def copy_selected_log(self):
    try:
      sel = self.log_view.get("sel.first", "sel.last")
      if sel:
        self.root.clipboard_clear()
        self.root.clipboard_append(sel)
        self.toast("Copied selection.", ok=True)
    except Exception:
      pass

  def test_dns(self):
    if not is_windows():
      messagebox.showinfo(APP_NAME, "Use: nslookup google.com 127.0.0.1")
      return
    code, out = run_cmd('nslookup google.com 127.0.0.1')
    messagebox.showinfo(APP_NAME, (out[:1800] if out else "No output"))

  def _poll_clipboard(self):
    try:
      if self.state.clipboard_scan:
        s=self.root.clipboard_get()
        s=sanitize_url(s)
        if s and s != self._clipboard_last and looks_like_url(s):
          self._clipboard_last=s
          with self.state.lock:
            blocked=set(self.state.blocked); allow=set(self.state.allow); ex=bool(self.state.enable_expand); explain=dict(self.state.domain_source)
          r=analyze_url(s, blocked, allow, enable_expand=ex, explain=explain)
          log_event({"type":"clipboard_scan","input":r.input,"host":r.host,"score":r.score,"verdict":r.verdict})
          self.refresh_log_view()
          self.refresh_report_preview()
          if self.state.notify_high and r.verdict in ("HIGH","CRITICAL"):
            self.toast(f"Clipboard flagged {r.verdict}: {r.host} ({r.score}/100)", ok=False)
    except Exception:
      pass
    self.root.after(1100, self._poll_clipboard)

  def _watchdog_loop(self):
    while True:
      try:
        time.sleep(4)
        if not is_windows() or not self.state.watchdog_revert:
          continue
        # If system DNS points to localhost but DNS filter isn't running -> revert to DHCP
        if windows_dns_is_pointing_localhost() and not self.state.running:
          iface=win_active_iface()
          if iface:
            ok,out=win_dns_reset_dhcp(iface)
            log_event({"type":"watchdog_revert","iface":iface,"ok":ok,"out":out})
      except Exception:
        pass

  def _policy_loop(self):
    while True:
      try:
        time.sleep(6)
        if not self.state.policy_enabled:
          time.sleep(10)
          continue
        interval = max(5, int(self.state.policy_interval_min))
        # run roughly each interval
        # if last fetch older than interval, fetch
        last = parse_utc_iso(self.state.last_policy_fetch) if self.state.last_policy_fetch else None
        now = datetime.datetime.now(datetime.timezone.utc)
        if (not last) or ((now - last).total_seconds() >= interval*60):
          pol = self.state.fetch_policy()
          if pol:
            self.state.apply_policy(pol)
            self.state.reload_lists()
      except Exception:
        pass

  def _new_domain_notify_loop(self):
    # poll log for new_domain_alert entries and toast
    last_seen_ts = ""
    while True:
      try:
        time.sleep(5)
        if not self.state.notify_high:
          continue
        path = os.path.join(LOG_DIR, "events.jsonl")
        if not os.path.exists(path):
          continue
        with open(path, "r", encoding="utf-8") as f:
          lines = f.readlines()[-120:]
        for ln in reversed(lines):
          try:
            j = json.loads(ln)
          except Exception:
            continue
          if j.get("type") == "new_domain_alert":
            ts = j.get("ts","")
            if ts and ts != last_seen_ts:
              last_seen_ts = ts
              dom = j.get("domain","")
              cnt = j.get("count","")
              self.toast(f"New-domain spike: {dom} ({cnt})", ok=False)
            break
      except Exception:
        pass

  def _startup_safety_check(self):
    try:
      if is_windows() and windows_dns_is_pointing_localhost() and not self.state.running:
        self.toast("System DNS=127.0.0.1 but protection is OFF. Click 'Fix Internet Now'.", ok=False)
    except Exception:
      pass
    self.refresh_temp_allows()
    self._refresh_status()

  def _auto_start_if_enabled(self):
    try:
      if self.state.auto_start_protection and not self.state.running:
        ok,msg=self.state.start_dns()
        log_event({"type":"auto_start_dns","ok":ok,"msg":msg})
      if self.state.auto_enable_system_dns and is_windows() and self.state.running:
        iface=win_active_iface()
        if iface:
          ok,out=win_dns_set_local(iface)
          log_event({"type":"auto_enable_system_dns","iface":iface,"ok":ok,"out":out})
    except Exception:
      pass
    self._refresh_status()

  # ------------------ Reports ------------------
  def _range_seconds(self) -> Optional[int]:
    v = self.rep_range.get()
    if "24" in v: return 24*3600
    if "7" in v: return 7*24*3600
    if "30" in v: return 30*24*3600
    return None  # all time

  def _load_events(self, max_lines=20000) -> List[dict]:
    path = os.path.join(LOG_DIR, "events.jsonl")
    if not os.path.exists(path):
      return []
    with open(path, "r", encoding="utf-8") as f:
      lines = f.readlines()[-max_lines:]
    ev=[]
    for ln in lines:
      try:
        j = json.loads(ln)
        if isinstance(j, dict):
          ev.append(j)
      except Exception:
        pass
    # apply range filter
    sec = self._range_seconds()
    if sec is None:
      return ev
    now = datetime.datetime.now(datetime.timezone.utc)
    out=[]
    for e in ev:
      ts = parse_utc_iso(e.get("ts",""))
      if ts and (now - ts).total_seconds() <= sec:
        out.append(e)
    return out

  def summarize_events(self, ev: List[dict]) -> dict:
    blocks={}
    sources={}
    scans=0
    high=0
    critical=0
    clipboard=0
    newdom=0
    for e in ev:
      t = e.get("type")
      if t == "dns_block":
        d = e.get("domain","")
        blocks[d] = blocks.get(d,0)+1
        s = e.get("source","")
        if s:
          sources[s] = sources.get(s,0)+1
      elif t == "manual_scan":
        scans += 1
        v = e.get("verdict","")
        if v == "HIGH": high += 1
        if v == "CRITICAL": critical += 1
      elif t == "clipboard_scan":
        clipboard += 1
      elif t == "new_domain_alert":
        newdom += 1
    top = sorted(blocks.items(), key=lambda kv: kv[1], reverse=True)[:15]
    return {
      "total_blocks": sum(blocks.values()),
      "unique_blocked_domains": len(blocks),
      "top_blocked": top,
      "sources": sources,
      "manual_scans": scans,
      "high_scans": high,
      "critical_scans": critical,
      "clipboard_scans": clipboard,
      "new_domain_alerts": newdom
    }

  def refresh_report_preview(self):
    ev = self._load_events()
    s = self.summarize_events(ev)
    lines=[]
    lines.append(f"Report Preview ({self.rep_range.get()}):")
    lines.append("")
    lines.append(f"- Total DNS blocks: {s['total_blocks']}")
    lines.append(f"- Unique blocked domains: {s['unique_blocked_domains']}")
    lines.append(f"- Manual scans: {s['manual_scans']} (HIGH={s['high_scans']}, CRITICAL={s['critical_scans']})")
    lines.append(f"- Clipboard scans: {s['clipboard_scans']}")
    lines.append(f"- New-domain alerts: {s['new_domain_alerts']}")
    lines.append("")
    lines.append("Top blocked domains:")
    for d,cnt in s["top_blocked"]:
      lines.append(f"  • {d} — {cnt}")
    if s["sources"]:
      lines.append("")
      lines.append("Block sources:")
      for k,v in sorted(s["sources"].items(), key=lambda kv: kv[1], reverse=True):
        lines.append(f"  • {k}: {v}")
    self.rep_out.delete("1.0","end")
    self.rep_out.insert("1.0","\n".join(lines))

  def export_csv(self):
    ev = self._load_events()
    if not ev:
      messagebox.showinfo(APP_NAME, "No events to export.")
      return
    dst = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
    if not dst:
      return
    try:
      keys=set()
      for e in ev:
        keys |= set(e.keys())
      keys = sorted(keys)
      with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for e in ev:
          w.writerow(e)
      self.toast("CSV exported.", ok=True)
    except Exception as e:
      messagebox.showerror(APP_NAME, f"CSV export failed:\n{e}")

  def export_pdf(self):
    ev = self._load_events()
    if not ev:
      messagebox.showinfo(APP_NAME, "No events to export.")
      return
    dst = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF","*.pdf")])
    if not dst:
      return
    try:
      s = self.summarize_events(ev)
      c = canvas.Canvas(dst, pagesize=A4)
      w,h = A4
      y = h - 48
      c.setFont("Helvetica-Bold", 16)
      c.drawString(48, y, "BaitBuster Incident Report")
      y -= 24
      c.setFont("Helvetica", 10)
      c.drawString(48, y, f"Generated: {utc_iso()}   Range: {self.rep_range.get()}")
      y -= 22
      c.setFont("Helvetica-Bold", 12)
      c.drawString(48, y, "Summary")
      y -= 16
      c.setFont("Helvetica", 10)
      for line in [
        f"Total DNS blocks: {s['total_blocks']}",
        f"Unique blocked domains: {s['unique_blocked_domains']}",
        f"Manual scans: {s['manual_scans']} (HIGH={s['high_scans']}, CRITICAL={s['critical_scans']})",
        f"Clipboard scans: {s['clipboard_scans']}",
        f"New-domain alerts: {s['new_domain_alerts']}",
      ]:
        c.drawString(60, y, "• " + line)
        y -= 14

      y -= 8
      c.setFont("Helvetica-Bold", 12)
      c.drawString(48, y, "Top Blocked Domains")
      y -= 16
      c.setFont("Helvetica", 10)
      for d,cnt in s["top_blocked"]:
        c.drawString(60, y, f"• {d} — {cnt}")
        y -= 14
        if y < 80:
          c.showPage()
          y = h - 60
          c.setFont("Helvetica", 10)

      if s["sources"]:
        y -= 8
        c.setFont("Helvetica-Bold", 12)
        c.drawString(48, y, "Block Sources")
        y -= 16
        c.setFont("Helvetica", 10)
        for k,v in sorted(s["sources"].items(), key=lambda kv: kv[1], reverse=True):
          c.drawString(60, y, f"• {k}: {v}")
          y -= 14
          if y < 80:
            c.showPage()
            y = h - 60
            c.setFont("Helvetica", 10)

      c.save()
      self.toast("PDF exported.", ok=True)
    except Exception as e:
      messagebox.showerror(APP_NAME, f"PDF export failed:\n{e}")

  # ------------------ Status + toast ------------------
  def toast(self, msg: str, ok: bool=True):
    self.msg_q.put((msg, ok))

  def _refresh_status(self):
    # interface
    if is_windows():
      iface=win_active_iface() or "(not detected)"
      self.iface.config(text=f"Interface: {iface}")
    else:
      self.iface.config(text="Interface: (Windows-only system DNS apply)")

    dns_local = is_windows() and windows_dns_is_pointing_localhost()

    if self.state.running:
      self.dns_lbl.config(text=f"DNS Filter: Running on {DNS_BIND_IP}:{DNS_BIND_PORT}", fg=C.OK)
      self.dot.config(fg=C.OK)
    else:
      self.dns_lbl.config(text="DNS Filter: Stopped", fg=C.MUTED)
      self.dot.config(fg=C.WARN if dns_local else C.MUTED)

    with self.state.lock:
      s=dict(self.state.stats)

    safe = "ON" if self.state.safe_mode else "OFF"
    self.quick.config(text=f"SafeMode={safe} | Blocked={s.get('blocked_count',0):,} | Allow={s.get('allow_count',0):,} | SystemDNS=localhost: {dns_local}")

    txt = (
      f"Blocked domains loaded: {s.get('blocked_count',0):,}\n"
      f"Allowlisted domains: {s.get('allow_count',0):,}\n"
      f"Temp allows active: {len(self.state.temp_allow)}\n"
      f"Blocks served (DNS): {s.get('hits_total',0):,}\n"
      f"Last blocked: {s.get('last_blocked','')}\n"
      f"Last blocked source: {s.get('last_block_source','')}\n"
      f"Last blocked mode: {s.get('last_block_mode','')}\n"
      f"Last blocked time: {s.get('last_blocked_ts','')}\n"
    )
    self.stats.configure(state="normal")
    self.stats.delete("1.0","end")
    self.stats.insert("1.0", txt)
    self.stats.configure(state="disabled")

    # status label for bar
    self.remote_status.config(text=f"Last fetch: {self.state.last_remote_fetch or '(none)'}")
    self.policy_status.config(text=f"Last policy fetch: {self.state.last_policy_fetch or '(none)'}")

    # badge
    if self._badge:
      self._badge.set_status(protected=self.state.running, warn=dns_local)

  def _tick(self):
    try:
      while True:
        msg, ok = self.msg_q.get_nowait()
        self.status.config(text=msg if len(msg) <= 46 else (msg[:46] + "…"))
        self.dot.config(fg=C.OK if ok else C.BAD)
    except queue.Empty:
      pass
    self._refresh_status()
    self.root.after(1100, self._tick)

  # ------------------ Tray ------------------
  def _start_tray(self):
    try:
      icon_path=os.path.join(BASE_DIR, "icon.ico")
      img=Image.open(icon_path)
    except Exception:
      img=Image.new("RGBA",(64,64),(0,0,0,0))

    menu = pystray.Menu(
      pystray.MenuItem("Open", lambda: self.root.after(0, self._show_from_tray)),
      pystray.MenuItem("Start DNS Filter", lambda: self.root.after(0, self.start_dns)),
      pystray.MenuItem("Stop DNS Filter", lambda: self.root.after(0, self.stop_dns)),
      pystray.MenuItem("Fix Internet (revert DNS)", lambda: self.root.after(0, self.fix_internet_now)),
      pystray.MenuItem("Quit", lambda: self.root.after(0, self.quit_app)),
    )
    self._tray = pystray.Icon("baitbuster", img, APP_NAME, menu)
    threading.Thread(target=self._tray.run, daemon=True).start()

  def _hide_to_tray(self):
    self.root.withdraw()
    self.toast("Running in background (tray).", ok=True)

  def _show_from_tray(self):
    self.root.deiconify()
    self.root.lift()
    try: self.root.focus_force()
    except Exception: pass

  # ------------------ Quit ------------------
  def quit_app(self):
    # auto-revert system dns if enabled
    try:
      if is_windows() and self.state.auto_revert_on_exit and windows_dns_is_pointing_localhost():
        iface=win_active_iface()
        if iface:
          ok,out=win_dns_reset_dhcp(iface)
          log_event({"type":"auto_revert_on_exit","iface":iface,"ok":ok,"out":out})
    except Exception:
      pass
    try:
      self.state.stop_dns()
    except Exception:
      pass
    try:
      if self._tray:
        self._tray.stop()
    except Exception:
      pass
    try:
      if self._badge:
        self._badge.hide()
    except Exception:
      pass
    self.root.destroy()

def main():
  ensure_dirs()
  st=AppState()
  ui=UI(st)
  ui.root.mainloop()

if __name__ == "__main__":
  main()
def get_downloads_dir(custom: str = "") -> str:
  try:
    if custom and custom.strip():
      return os.path.abspath(os.path.expanduser(custom.strip()))
  except Exception:
    pass
  return os.path.join(os.path.expanduser("~"), "Downloads")

RISKY_EXTS = {".exe",".msi",".scr",".bat",".cmd",".ps1",".vbs",".js",".jse",".wsf",".lnk",".hta",".jar",".iso",".img",".cab",".dll",".sys",".reg",".chm",".zip",".rar",".7z",".docm",".xlsm",".pptm"}

def is_risky_file(path: str) -> bool:
  ext = os.path.splitext(path)[1].lower()
  return ext in RISKY_EXTS

def defender_scan_file(path: str) -> (bool, str):
  """Attempts to scan a file using Windows Defender (if present)."""
  if not is_windows():
    return False, "Windows-only"
  try:
    p1 = os.path.join(os.environ.get("ProgramFiles","C:\\Program Files"), "Windows Defender", "MpCmdRun.exe")
    p2 = os.path.join(os.environ.get("ProgramFiles","C:\\Program Files"), "Windows Defender", "MpCmdRun.exe")
    mp = p1 if os.path.exists(p1) else p2
    if os.path.exists(mp):
      # -ScanType 3 = custom scan; -File supports a single file
      res = subprocess.run([mp, "-Scan", "-ScanType", "3", "-File", path], capture_output=True, text=True)
      ok = (res.returncode == 0)
      out = (res.stdout or "") + (res.stderr or "")
      return ok, out.strip()[:800]
  except Exception as e:
    return False, str(e)
  # fallback to PowerShell Start-MpScan (folder based)
  try:
    res = subprocess.run(["powershell","-NoProfile","-Command", f"Start-MpScan -ScanPath '{path}'"], capture_output=True, text=True)
    ok = (res.returncode == 0)
    out = (res.stdout or "") + (res.stderr or "")
    return ok, out.strip()[:800]
  except Exception as e:
    return False, str(e)

def quarantine_file(path: str) -> str:
  ensure_dirs()
  base = os.path.basename(path)
  ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
  dst = os.path.join(QUAR_DIR, f"{ts}__{base}")
  # avoid overwrite
  i=1
  orig_dst=dst
  while os.path.exists(dst):
    dst = orig_dst.replace("__", f"__{i}_", 1)
    i += 1
  shutil.move(path, dst)
  return dst


