import os
import sys
import time
import json
import threading
import tempfile
import shutil
import subprocess
import requests
import hashlib
import logging
import psutil
import pyclamd
import signal
import base64
import secrets

from PySide6 import QtCore, QtWidgets, QtGui
import qtawesome as qta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- TGCRYPTO AES-256-IGE ---
try:
    from tgcrypto import ige256_decrypt, ige256_encrypt
except ImportError:
    raise ImportError("Install tgcrypto: pip install https://github.com/pyrogram/tgcrypto/archive/master.zip")

# --- Constants ---
VTX_NAME = "VTX"
VTX_ICON = "fa5s.shield-alt"
AES_KEY = bytes.fromhex("eeef64a99c54822173ddd8f895e0a43273dc0e4a44ca9560052fb5a76b2fd8f7")
QUARANTINE_DIR = os.path.expanduser("~/.vtx_quarantine")
PHISHING_URLS = set([
    "portfolio-trezor-cdn.webflow.io",
    "agodahotelmall.com",
    "refundagoda.life",
    "parmagicl.com",
    "shanghaianlong.com",
    "agodamall.net",
    "stmpx0-gm.myshopify.com",
    "888nyw.com",
    "verifications.smcavalier.com",
    "coupangshopag.shop",
    "thanhtoanhoahongcoupangltd.com",
    "galxboysa.com",
    "allegro.pi-993120462528302.rest",
])
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")

def random_iv():
    return secrets.token_bytes(32)

def aes256_ige_encrypt(data, key):
    iv = random_iv()
    ciphertext = ige256_encrypt(key, iv, data)
    return iv + ciphertext

def aes256_ige_decrypt(data, key):
    iv = data[:32]
    ciphertext = data[32:]
    return ige256_decrypt(key, iv, ciphertext)

def ensure_dir(p):
    if not os.path.exists(p):
        os.makedirs(p, exist_ok=True)

def get_firefox_profile_path():
    from glob import glob
    mozilla = os.path.expanduser("~/.mozilla/firefox")
    if not os.path.isdir(mozilla):
        return None
    for profile in glob(os.path.join(mozilla, "*.default*")):
        return profile
    return None

def install_mitmproxy_ca():
    import subprocess, time, signal
    proc = subprocess.Popen(["mitmdump", "-q"])
    time.sleep(5)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    ca_dir = os.path.expanduser("~/.mitmproxy")
    ca_cert = os.path.join(ca_dir, "mitmproxy-ca-cert.pem")
    if not os.path.exists(ca_cert):
        raise Exception("mitmproxy CA cert not found, run mitmproxy once manually")
    if os.path.exists("/usr/local/share/ca-certificates"):
        shutil.copy(ca_cert, "/usr/local/share/ca-certificates/vtx-mitmproxy.crt")
        subprocess.run(["update-ca-certificates"])
    ff_profile = get_firefox_profile_path()
    if ff_profile:
        certdb = os.path.join(ff_profile, "cert9.db")
        if os.path.exists(certdb):
            subprocess.run([
                "certutil", "-A", "-n", "VTX MITM CA", "-t", "C,,", "-i", ca_cert,
                "-d", f"sql:{ff_profile}"])
    return ca_cert

def set_firefox_proxy(port):
    ff_profile = get_firefox_profile_path()
    if not ff_profile:
        return
    prefs = os.path.join(ff_profile, "prefs.js")
    with open(prefs, "a") as f:
        f.write(f'''
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", {port});
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", {port});
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");
''')

def is_url_phishing(url):
    for u in PHISHING_URLS:
        if u in url:
            return True
    return False

def vt_url_lookup(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(hashlib.sha256(url.encode()).digest()).decode().strip('=')}",
            headers=headers)
        if resp.status_code == 200:
            js = resp.json()
            if js.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                return True
    except Exception as e:
        logging.error(f"VT lookup failed: {e}")
    return False

def create_mitm_addon():
    addon_code = '''
from mitmproxy import http

PHISHING_URLS = {
    "portfolio-trezor-cdn.webflow.io",
    "agodahotelmall.com",
    "refundagoda.life",
    "parmagicl.com",
    "shanghaianlong.com",
    "agodamall.net",
    "stmpx0-gm.myshopify.com",
    "888nyw.com",
    "verifications.smcavalier.com",
    "coupangshopag.shop",
    "thanhtoanhoahongcoupangltd.com",
    "galxboysa.com",
    "allegro.pi-993120462528302.rest",
}

def is_url_phishing(url):
    for u in PHISHING_URLS:
        if u in url:
            return True
    return False

def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    if "/api/" in url or "/telemetry/" in url:
        return
    if is_url_phishing(url):
        flow.response = http.HTTPResponse.make(
            200,
            """
<script>
(function() {
    let overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.top = 0;
    overlay.style.left = 0;
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.backgroundColor = "rgba(255,0,0,0.9)";
    overlay.style.zIndex = 999999;
    overlay.style.color = "#fff";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.innerHTML = `
        <h1 style='font-size: 32px; margin: 0;'>⚠️ NEBEZPEČNÁ STRÁNKA</h1>
        <p style='font-size: 20px;'>Tato stránka byla označena jako potenciálně škodlivá.</p>
        <button onclick="location.href='https://www.google.com'" style='margin-top:20px;padding:10px 20px;font-size:16px;'>Opustit stránku</button>
    `;
    document.body.appendChild(overlay);
})();
</script>
            """,
            {"Content-Type": "text/html"},
        )
'''
    fname = os.path.abspath("vtx_mitm_addon.py")
    with open(fname, "w") as f:
        f.write(addon_code)
    return fname

class Watermark(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.FramelessWindowHint | QtCore.Qt.Tool)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setAttribute(QtCore.Qt.WA_ShowWithoutActivating)
        self.setFixedSize(180, 60)
        self.move(QtWidgets.QApplication.primaryScreen().geometry().width() - 200, 40)
        self.button = QtWidgets.QPushButton("🛑 STOP", self)
        self.button.setStyleSheet("background:rgba(200,0,0,0.7);color:white;font-size:18px;border-radius:10px;")
        self.button.setGeometry(0, 0, 180, 60)
        self.button.clicked.connect(self.stop_vtx)
        self.show()

    def stop_vtx(self):
        QtWidgets.QMessageBox.critical(self, "VTX", "Antivirus will stop and proxy will be disabled!")
        os._exit(0)

def notify(title, msg, icon=None):
    icon = icon or VTX_ICON
    try:
        from gi.repository import Notify
        Notify.init(VTX_NAME)
        n = Notify.Notification.new(title, msg)
        n.show()
    except Exception:
        mbox = QtWidgets.QMessageBox()
        mbox.setWindowTitle(title)
        mbox.setText(msg)
        mbox.exec()

def firewall_block_ports():
    os.system("iptables -A OUTPUT -p tcp --dport 4444 -j DROP")
    os.system("iptables -A OUTPUT -p tcp --dport 3389 -j DROP")

def firewall_unblock_ports():
    os.system("iptables -D OUTPUT -p tcp --dport 4444 -j DROP")
    os.system("iptables -D OUTPUT -p tcp --dport 3389 -j DROP")

def list_video_audio_devices():
    try:
        import pyudev
        context = pyudev.Context()
        return [dev.device_node for dev in context.list_devices(subsystem="video4linux")]
    except Exception:
        return []

def block_webcam_mic():
    for dev in list_video_audio_devices():
        try:
            os.chmod(dev, 0o000)
        except Exception: pass

def unblock_webcam_mic():
    for dev in list_video_audio_devices():
        try:
            os.chmod(dev, 0o666)
        except Exception: pass

def ask_webcam_mic_access():
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
    reply = QtWidgets.QMessageBox.question(
        None, "Webcam/Microphone Access Request",
        "An application wants to access your webcam or microphone. Allow?",
        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
    return reply == QtWidgets.QMessageBox.Yes

def quarantine_file(filepath):
    ensure_dir(QUARANTINE_DIR)
    with open(filepath, "rb") as f:
        data = f.read()
    enc = aes256_ige_encrypt(data, AES_KEY)
    qpath = os.path.join(QUARANTINE_DIR, os.path.basename(filepath) + ".vtxq")
    with open(qpath, "wb") as f:
        f.write(enc)
    os.remove(filepath)
    logging.info(f"Quarantined and encrypted {filepath} to {qpath}")

class DownloadHandler(FileSystemEventHandler):
    def __init__(self, avscan_cb):
        self.avscan_cb = avscan_cb

    def on_created(self, event):
        if not event.is_directory:
            self.avscan_cb(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.avscan_cb(event.src_path)

class VTXCoreDaemon(threading.Thread):
    def __init__(self, download_dirs, temp_dirs):
        super().__init__(daemon=True)
        self.download_dirs = download_dirs
        self.temp_dirs = temp_dirs
        self.clamd = pyclamd.ClamdUnixSocket()
        self.observer = Observer()

    def run(self):
        handler = DownloadHandler(self.scan_file)
        for d in self.download_dirs + self.temp_dirs:
            ensure_dir(d)
            self.observer.schedule(handler, d, recursive=False)
        self.observer.start()
        while True:
            time.sleep(1)

    def scan_file(self, path):
        try:
            logging.info(f"Scanning {path}")
            result = self.clamd.scan_file(path)
            if result:
                status = result[path][0]
                logging.warning(f"Infected: {path} ({status})")
                alert = f"🛑 Virus detected: {status}\nFile: {path}\nKeep or Quarantine?"
                app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
                reply = QtWidgets.QMessageBox.warning(
                    None, "VTX Alert", alert,
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
                if reply == QtWidgets.QMessageBox.No:
                    quarantine_file(path)
                    notify("VTX", f"File quarantined: {path}")
                else:
                    notify("VTX", f"File kept: {path}")
        except Exception as e:
            logging.error(f"Error scanning {path}: {e}")

def start_mitmproxy(port=8080):
    ca_cert = install_mitmproxy_ca()
    set_firefox_proxy(port)
    addon_path = create_mitm_addon()
    subprocess.Popen([
        "mitmdump",
        "-p", str(port),
        "-s", addon_path,
        "--no-http2"
    ])

def watchdog_loop():
    while True:
        if not any("av.py" in p.cmdline() for p in psutil.process_iter()):
            logging.info("Agent not running, restarting")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        time.sleep(10)

class AVMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            self.setWindowIcon(qta.icon('fa5s.shield-alt', color='blue'))
        except Exception:
            self.setWindowIcon(QtGui.QIcon())
        self.setWindowTitle(f"{VTX_NAME} Antivirus")
        self.resize(660, 460)
        self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
        self.anim = QtCore.QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(1200)
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.start()
        w = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout()
        label = QtWidgets.QLabel()
        label.setPixmap(qta.icon('fa5s.bug', color='red').pixmap(64, 64))
        label.setAlignment(QtCore.Qt.AlignCenter)
        v.addWidget(label)
        title = QtWidgets.QLabel(f"{VTX_NAME} Antivirus is ACTIVE 🔒")
        title.setStyleSheet("font-size:28px;color:#3498db;")
        title.setAlignment(QtCore.Qt.AlignCenter)
        v.addWidget(title)
        self.status = QtWidgets.QLabel("🟢 Real-time protection enabled\n🕒 " + time.strftime("%Y-%m-%d %H:%M:%S"))
        self.status.setAlignment(QtCore.Qt.AlignCenter)
        v.addWidget(self.status)
        hb = QtWidgets.QHBoxLayout()
        self.scan_btn = QtWidgets.QPushButton(qta.icon('fa5s.search', color='green'), "Manual Scan")
        self.scan_btn.clicked.connect(self.manual_scan)
        hb.addWidget(self.scan_btn)
        self.quar_btn = QtWidgets.QPushButton(qta.icon('fa5s.lock', color='orange'), "Show Quarantine")
        self.quar_btn.clicked.connect(self.show_quarantine)
        hb.addWidget(self.quar_btn)
        self.settings_btn = QtWidgets.QPushButton(qta.icon('fa5s.cog', color='gray'), "Settings")
        self.settings_btn.clicked.connect(self.show_settings)
        hb.addWidget(self.settings_btn)
        v.addLayout(hb)
        w.setLayout(v)
        self.setCentralWidget(w)
        self.watermark = Watermark()

    def manual_scan(self):
        path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not path: return
        self.status.setText("Scanning...")
        clamd = pyclamd.ClamdUnixSocket()
        for root, dirs, files in os.walk(path):
            for f in files:
                full = os.path.join(root, f)
                res = clamd.scan_file(full)
                if res:
                    status = res[full][0]
                    QtWidgets.QMessageBox.warning(self, "VTX Alert",
                        f"🛑 Virus detected: {status}\nFile: {full}\nKeep or Quarantine?")
                    quarantine_file(full)
        self.status.setText("Scan finished.")

    def show_quarantine(self):
        files = os.listdir(QUARANTINE_DIR) if os.path.exists(QUARANTINE_DIR) else []
        msg = "Quarantined files:\n" + "\n".join(files) if files else "No files in quarantine."
        QtWidgets.QMessageBox.information(self, "VTX Quarantine", msg)

    def show_settings(self):
        QtWidgets.QMessageBox.information(self, "Settings",
            "Firewall protection: ENABLED\nWebcam/mic protection: ENABLED\nStart on boot: ENABLED\nService: VTX\n")

def write_systemd_service():
    svc = f"""[Unit]
Description=VTX Antivirus Daemon
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    with open("/etc/systemd/system/vtx.service", "w") as f:
        f.write(svc)
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", "vtx"])
    subprocess.run(["systemctl", "start", "vtx"])

def main():
    ensure_dir(QUARANTINE_DIR)
    firewall_block_ports()
    block_webcam_mic()
    write_systemd_service()
    downloads = [os.path.expanduser("~/Downloads")]
    tempdirs = [tempfile.gettempdir(), "/tmp"]
    daemon = VTXCoreDaemon(downloads, tempdirs)
    daemon.start()
    mitm_thread = threading.Thread(target=start_mitmproxy, kwargs={"port": 8080}, daemon=True)
    mitm_thread.start()
    wd = threading.Thread(target=watchdog_loop, daemon=True)
    wd.start()
    app = QtWidgets.QApplication(sys.argv)
    window = AVMainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        firewall_unblock_ports()
        unblock_webcam_mic()
