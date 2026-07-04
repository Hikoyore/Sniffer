#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from collections import defaultdict
from datetime import datetime

from PySide6.QtWidgets import *
from PySide6.QtCore import *
from PySide6.QtGui import *

import psutil
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR


class SnifferThread(QThread):
    dns_signal = Signal(str, str, str, str)
    tcp_signal = Signal(str, dict)
    stats_signal = Signal(int, int, int)
    error_signal = Signal(str)
    log_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self):
        super().__init__()
        self.running = False
        self.domains = set()
        self.ip_domain_map = {}
        self.connections = {}
        self.packet_counts = defaultdict(int)
        self.bytes_sent = defaultdict(int)
        self.process_apps = defaultdict(int)
        self.packets_received = 0
        self.start_time = None
        self.lock = QMutex()

    def run(self):
        try:
            self.running = True
            self.start_time = datetime.now()
            self.log_signal.emit("=== SNIFFER THREAD STARTED ===")
            sniff(filter="ip", prn=self.packet_callback, store=False)
        except PermissionError as e:
            self.error_signal.emit(f"Permission error: {e}")
        except Exception as e:
            self.error_signal.emit(f"Sniff error: {e}")
        finally:
            self.running = False
            self.finished_signal.emit()

    def stop(self):
        self.running = False

    def packet_callback(self, packet):
        if not self.running:
            return
        with QMutexLocker(self.lock):
            self.packets_received += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)
                proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
                proto_name = proto_names.get(proto, f"Proto-{proto}")
                self.packet_counts[proto_name] += 1
                self.bytes_sent[proto_name] += size
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    query = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                    if query and query not in self.domains:
                        self.domains.add(query)
                        app = "Unknown"
                        if packet.haslayer(UDP):
                            app = self.get_process_by_port(packet[UDP].sport, 'udp')
                        self.process_apps[app] += 1
                        if packet.haslayer(IP):
                            self.ip_domain_map[dst_ip] = query
                        self.dns_signal.emit(query, src_ip, app, timestamp)
                except:
                    pass
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                if tcp.flags & 0x10:
                    key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    app = self.get_process_by_port(src_port, 'tcp')
                    domain = self.ip_domain_map.get(dst_ip, "Unknown")
                    if key not in self.connections:
                        self.connections[key] = {
                            'first_seen': timestamp,
                            'process': app,
                            'packets': 0,
                            'bytes': 0,
                            'domain': domain
                        }
                    self.connections[key]['packets'] += 1
                    self.connections[key]['bytes'] += size
                    self.process_apps[app] += 1
                    if self.connections[key]['packets'] % 3 == 0:
                        self.tcp_signal.emit(key, self.connections[key])
            if self.packets_received % 10 == 0:
                self.stats_signal.emit(
                    self.packets_received,
                    len(self.domains),
                    len(self.connections)
                )

    def get_process_by_port(self, local_port, protocol='tcp'):
        try:
            connections = psutil.net_connections(kind=protocol)
            for conn in connections:
                if conn.laddr and conn.laddr.port == local_port:
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            return f"{proc.name()} (PID: {conn.pid})"
                        except:
                            return f"PID: {conn.pid}"
            return "System process"
        except:
            return "Unknown"

    def get_stats(self):
        with QMutexLocker(self.lock):
            return {
                'packets': self.packets_received,
                'domains': len(self.domains),
                'connections': len(self.connections),
                'packet_counts': dict(self.packet_counts),
                'bytes_sent': dict(self.bytes_sent),
                'process_apps': dict(self.process_apps),
                'start_time': self.start_time
            }


class SnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sniffer_thread = None
        self.lang = 'en'
        self.initUI()
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats)
        self.stats_timer.start(2000)
        self.statusBar.showMessage('Ready. Press "Start" to begin.')

    def initUI(self):
        self.setWindowTitle('Sniffer')
        self.setGeometry(100, 100, 1300, 750)

        self.setLayoutDirection(Qt.LeftToRight)

        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e1e; }
            QTabWidget::pane { border: 1px solid #444; background: #1e1e1e; }
            QTabBar::tab { background: #2d2d2d; color: #ccc; padding: 8px 25px; }
            QTabBar::tab:selected { background: #3d3d3d; color: white; border-bottom: 2px solid #4a9eff; }
            QTableWidget { 
                background: #1a1a1a; 
                color: #ddd; 
                gridline-color: #333; 
                alternate-background-color: #252525;
                direction: ltr;
            }
            QTableWidget::item { padding: 5px; direction: ltr; }
            QHeaderView::section { 
                background: #2d2d2d; 
                color: #aaa; 
                padding: 6px; 
                border: 1px solid #3d3d3d; 
                font-weight: bold;
                direction: ltr;
            }
            QPushButton { background: #4a9eff; color: white; border: none; padding: 8px 25px; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background: #6ab0ff; }
            QPushButton:disabled { background: #444; color: #888; }
            QPushButton#danger { background: #ff6b6b; }
            QPushButton#danger:hover { background: #ff8a8a; }
            QLabel { color: #ddd; font-size: 13px; }
            QListWidget { background: #1a1a1a; color: #ddd; border: 1px solid #333; direction: ltr; }
            QTextEdit { background: #1a1a1a; color: #ddd; border: 1px solid #333; font-family: monospace; font-size: 12px; direction: ltr; }
            QStatusBar { background: #2d2d2d; color: #aaa; }
            QLineEdit { background: #2d2d2d; color: #ddd; border: 1px solid #444; padding: 5px; border-radius: 3px; direction: ltr; }
            QComboBox {
                background: #2d2d2d;
                color: #ddd;
                border: 1px solid #444;
                padding: 5px;
                border-radius: 3px;
                direction: ltr;
            }
            QComboBox::drop-down { border: none; }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #aaa;
                margin-right: 5px;
            }
            QComboBox QAbstractItemView {
                background: #2d2d2d;
                color: #ddd;
                selection-background-color: #4a9eff;
                selection-color: white;
            }
            QScrollBar:vertical { background: #2b2b2b; width: 12px; }
            QScrollBar::handle:vertical { background: #4a4a4a; border-radius: 6px; min-height: 20px; }
            QScrollBar::handle:vertical:hover { background: #5a5a5a; }
            QScrollBar:horizontal { background: #2b2b2b; height: 12px; }
            QScrollBar::handle:horizontal { background: #4a4a4a; border-radius: 6px; min-width: 20px; }
            QScrollBar::handle:horizontal:hover { background: #5a5a5a; }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        central.setLayoutDirection(Qt.LeftToRight)

        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)

        cp = QHBoxLayout()
        cp.setSpacing(15)

        self.status_label = QLabel('Stopped')
        self.status_label.setStyleSheet('font-size: 14px; font-weight: bold; color: #ff6b6b;')
        cp.addWidget(self.status_label)

        self.packets_label = QLabel('Packets: 0')
        self.packets_label.setStyleSheet('font-size: 13px; color: #4a9eff;')
        cp.addWidget(self.packets_label)

        self.domains_label = QLabel('Domains: 0')
        self.domains_label.setStyleSheet('font-size: 13px; color: #ffd93d;')
        cp.addWidget(self.domains_label)

        self.time_label = QLabel('Time: 00:00:00')
        self.time_label.setStyleSheet('font-size: 13px; color: #6bcb77;')
        cp.addWidget(self.time_label)

        cp.addStretch()

        self.lang_btn = QPushButton('RU')
        self.lang_btn.setStyleSheet('background: #ff8c00;')
        self.lang_btn.clicked.connect(self.toggle_lang)
        cp.addWidget(self.lang_btn)

        self.start_btn = QPushButton('Start')
        self.start_btn.clicked.connect(self.start_sniffing)
        cp.addWidget(self.start_btn)

        self.stop_btn = QPushButton('Stop')
        self.stop_btn.setObjectName('danger')
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.stop_btn.setEnabled(False)
        cp.addWidget(self.stop_btn)

        self.clear_btn = QPushButton('Clear')
        self.clear_btn.clicked.connect(self.clear_data)
        cp.addWidget(self.clear_btn)

        main_layout.addLayout(cp)

        self.tabs = QTabWidget()
        self.tabs.setLayoutDirection(Qt.LeftToRight)
        main_layout.addWidget(self.tabs)

        dns_tab = QWidget()
        dns_tab.setLayoutDirection(Qt.LeftToRight)
        dns_layout = QVBoxLayout(dns_tab)

        self.dns_search = QLineEdit()
        self.dns_search.setPlaceholderText('Filter by domain...')
        self.dns_search.textChanged.connect(self.filter_dns)
        dns_layout.addWidget(self.dns_search)

        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(4)
        self.dns_table.setHorizontalHeaderLabels(['Time', 'Domain', 'IP Address', 'Application'])
        self.dns_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.dns_table.setAlternatingRowColors(True)
        self.dns_table.setLayoutDirection(Qt.LeftToRight)
        self.dns_table.horizontalHeader().setLayoutDirection(Qt.LeftToRight)
        self.dns_table.horizontalHeader().setSectionsMovable(True)
        self.dns_table.setSortingEnabled(True)
        dns_layout.addWidget(self.dns_table)
        self.tabs.addTab(dns_tab, 'DNS')

        tcp_tab = QWidget()
        tcp_tab.setLayoutDirection(Qt.LeftToRight)
        tcp_layout = QVBoxLayout(tcp_tab)

        self.tcp_table = QTableWidget()
        self.tcp_table.setColumnCount(6)
        self.tcp_table.setHorizontalHeaderLabels(['Connection', 'Domain', 'Application', 'Packets', 'Bytes', 'First Seen'])
        self.tcp_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tcp_table.setAlternatingRowColors(True)
        self.tcp_table.setLayoutDirection(Qt.LeftToRight)
        self.tcp_table.horizontalHeader().setLayoutDirection(Qt.LeftToRight)
        self.tcp_table.horizontalHeader().setSectionsMovable(True)
        self.tcp_table.setSortingEnabled(True)
        tcp_layout.addWidget(self.tcp_table)
        self.tabs.addTab(tcp_tab, 'TCP')

        apps_tab = QWidget()
        apps_tab.setLayoutDirection(Qt.LeftToRight)
        apps_layout = QVBoxLayout(apps_tab)

        apps_control = QHBoxLayout()
        self.sort_label = QLabel('Sort:')
        apps_control.addWidget(self.sort_label)
        self.sort_combo = QComboBox()
        self.sort_combo.addItems(['By count', 'By name (A-Z)', 'By name (Z-A)'])
        self.sort_combo.currentIndexChanged.connect(self.update_apps_list)
        apps_control.addWidget(self.sort_combo)
        apps_control.addStretch()
        apps_layout.addLayout(apps_control)

        self.apps_list = QListWidget()
        self.apps_list.setLayoutDirection(Qt.LeftToRight)
        apps_layout.addWidget(self.apps_list)
        self.tabs.addTab(apps_tab, 'Applications')

        stats_tab = QWidget()
        stats_tab.setLayoutDirection(Qt.LeftToRight)
        stats_layout = QVBoxLayout(stats_tab)

        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setLayoutDirection(Qt.LeftToRight)
        stats_layout.addWidget(self.stats_text)
        self.tabs.addTab(stats_tab, 'Statistics')

        log_tab = QWidget()
        log_tab.setLayoutDirection(Qt.LeftToRight)
        log_layout = QVBoxLayout(log_tab)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet('font-family: monospace; font-size: 11px; direction: ltr;')
        self.log_text.setLayoutDirection(Qt.LeftToRight)
        log_layout.addWidget(self.log_text)
        self.tabs.addTab(log_tab, 'Log')

        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        self.lang_widgets = {
            'en': {
                'window_title': 'Sniffer',
                'status_stopped': 'Stopped',
                'status_running': 'Running',
                'packets': 'Packets',
                'domains': 'Domains',
                'time': 'Time',
                'start': 'Start',
                'stop': 'Stop',
                'clear': 'Clear',
                'filter': 'Filter by domain...',
                'dns_headers': ['Time', 'Domain', 'IP Address', 'Application'],
                'tcp_headers': ['Connection', 'Domain', 'Application', 'Packets', 'Bytes', 'First Seen'],
                'sort_label': 'Sort:',
                'sort_items': ['By count', 'By name (A-Z)', 'By name (Z-A)'],
                'tab_dns': 'DNS',
                'tab_tcp': 'TCP',
                'tab_apps': 'Applications',
                'tab_stats': 'Statistics',
                'tab_log': 'Log',
                'status_ready': 'Ready. Press "Start" to begin.',
                'status_running_msg': 'Sniffer is running...',
                'status_stopped_msg': 'Sniffer stopped',
                'status_cleared': 'Data cleared',
                'no_data': 'No data',
                'stats_title': '=== STATISTICS ===',
                'stats_uptime': 'Uptime',
                'stats_packets': 'Packets',
                'stats_domains': 'Domains',
                'stats_connections': 'TCP Connections',
                'stats_protocols': 'Protocols',
                'stats_no_data': 'No data. Start the sniffer.'
            },
            'ru': {
                'window_title': 'Sniffer',
                'status_stopped': 'Остановлен',
                'status_running': 'Работает',
                'packets': 'Пакетов',
                'domains': 'Доменов',
                'time': 'Время',
                'start': 'Старт',
                'stop': 'Стоп',
                'clear': 'Очистить',
                'filter': 'Фильтр по домену...',
                'dns_headers': ['Время', 'Домен', 'IP-адрес', 'Приложение'],
                'tcp_headers': ['Соединение', 'Домен', 'Приложение', 'Пакеты', 'Байты', 'Впервые'],
                'sort_label': 'Сортировка:',
                'sort_items': ['По количеству', 'По имени (А-Я)', 'По имени (Я-А)'],
                'tab_dns': 'DNS',
                'tab_tcp': 'TCP',
                'tab_apps': 'Приложения',
                'tab_stats': 'Статистика',
                'tab_log': 'Лог',
                'status_ready': 'Готов. Нажмите "Старт" для начала.',
                'status_running_msg': 'Сниффер запущен...',
                'status_stopped_msg': 'Сниффер остановлен',
                'status_cleared': 'Данные очищены',
                'no_data': 'Нет данных',
                'stats_title': '=== СТАТИСТИКА ===',
                'stats_uptime': 'Время работы',
                'stats_packets': 'Пакетов',
                'stats_domains': 'Доменов',
                'stats_connections': 'TCP-соединений',
                'stats_protocols': 'Протоколы',
                'stats_no_data': 'Нет данных. Запустите сниффер.'
            }
        }

    def toggle_lang(self):
        self.lang = 'ru' if self.lang == 'en' else 'en'
        self.lang_btn.setText('EN' if self.lang == 'en' else 'RU')
        self.update_ui_lang()

    def update_ui_lang(self):
        t = self.lang_widgets[self.lang]
        self.setWindowTitle(t['window_title'])
        self.status_label.setText(t['status_stopped'])
        self.packets_label.setText(f"{t['packets']}: 0")
        self.domains_label.setText(f"{t['domains']}: 0")
        self.time_label.setText(f"{t['time']}: 00:00:00")
        self.start_btn.setText(t['start'])
        self.stop_btn.setText(t['stop'])
        self.clear_btn.setText(t['clear'])
        self.dns_search.setPlaceholderText(t['filter'])
        self.dns_table.setHorizontalHeaderLabels(t['dns_headers'])
        self.tcp_table.setHorizontalHeaderLabels(t['tcp_headers'])
        self.tabs.setTabText(0, t['tab_dns'])
        self.tabs.setTabText(1, t['tab_tcp'])
        self.tabs.setTabText(2, t['tab_apps'])
        self.tabs.setTabText(3, t['tab_stats'])
        self.tabs.setTabText(4, t['tab_log'])
        self.sort_label.setText(t['sort_label'])
        for i, item in enumerate(t['sort_items']):
            self.sort_combo.setItemText(i, item)
        if self.sniffer_thread and self.sniffer_thread.running:
            self.status_label.setText(t['status_running'])
            self.statusBar.showMessage(t['status_running_msg'])
        else:
            self.statusBar.showMessage(t['status_ready'])
        self.update_stats()
        self.update_apps_list()

    def log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        full = f"[{timestamp}] {msg}"
        print(full)
        self.log_text.append(full)
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_text.setTextCursor(cursor)
        self.log_text.ensureCursorVisible()

    def on_dns(self, query, src_ip, app, timestamp):
        row = self.dns_table.rowCount()
        self.dns_table.insertRow(row)
        self.dns_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.dns_table.setItem(row, 1, QTableWidgetItem(query))
        self.dns_table.setItem(row, 2, QTableWidgetItem(src_ip))
        self.dns_table.setItem(row, 3, QTableWidgetItem(app))
        self.dns_table.scrollToBottom()
        t = self.lang_widgets[self.lang]
        self.domains_label.setText(f"{t['domains']}: {self.dns_table.rowCount()}")

    def on_tcp(self, key, conn_data):
        found = False
        for row in range(self.tcp_table.rowCount()):
            if self.tcp_table.item(row, 0).text() == key:
                self.tcp_table.setItem(row, 3, QTableWidgetItem(str(conn_data['packets'])))
                self.tcp_table.setItem(row, 4, QTableWidgetItem(str(conn_data['bytes'])))
                found = True
                break
        if not found:
            row = self.tcp_table.rowCount()
            self.tcp_table.insertRow(row)
            self.tcp_table.setItem(row, 0, QTableWidgetItem(key))
            self.tcp_table.setItem(row, 1, QTableWidgetItem(conn_data['domain']))
            self.tcp_table.setItem(row, 2, QTableWidgetItem(conn_data['process']))
            self.tcp_table.setItem(row, 3, QTableWidgetItem(str(conn_data['packets'])))
            self.tcp_table.setItem(row, 4, QTableWidgetItem(str(conn_data['bytes'])))
            self.tcp_table.setItem(row, 5, QTableWidgetItem(conn_data['first_seen']))
            self.tcp_table.scrollToBottom()

    def on_stats(self, packets, domains, connections):
        t = self.lang_widgets[self.lang]
        self.packets_label.setText(f"{t['packets']}: {packets}")
        self.domains_label.setText(f"{t['domains']}: {domains}")

    def on_error(self, msg):
        self.log(f"ERROR: {msg}")
        self.statusBar.showMessage(msg[:100])
        self.stop_sniffing()

    def on_finished(self):
        self.log("Sniffer finished")
        self.stop_sniffing()

    def filter_dns(self, text):
        text = text.lower()
        for row in range(self.dns_table.rowCount()):
            domain = self.dns_table.item(row, 1).text().lower()
            self.dns_table.setRowHidden(row, text not in domain)

    def update_apps_list(self):
        if not self.sniffer_thread:
            return
        stats = self.sniffer_thread.get_stats()
        apps = stats.get('process_apps', {})
        if not apps:
            self.apps_list.clear()
            self.apps_list.addItem(self.lang_widgets[self.lang]['no_data'])
            return
        sort_type = self.sort_combo.currentIndex()
        if sort_type == 0:
            sorted_apps = sorted(apps.items(), key=lambda x: x[1], reverse=True)
        elif sort_type == 1:
            sorted_apps = sorted(apps.items(), key=lambda x: x[0].lower())
        else:
            sorted_apps = sorted(apps.items(), key=lambda x: x[0].lower(), reverse=True)
        self.apps_list.clear()
        for app, count in sorted_apps[:50]:
            emoji = " "
            if any(x in app.lower() for x in ['chrome', 'firefox', 'edge', 'opera', 'browser']):
                emoji = "🌐"
            elif any(x in app.lower() for x in ['telegram', 'discord', 'whatsapp', 'skype']):
                emoji = "💬"
            elif 'spotify' in app.lower():
                emoji = "🎵"
            elif 'steam' in app.lower() or 'game' in app.lower():
                emoji = "🎮"
            elif 'python' in app.lower():
                emoji = "🐍"
            elif 'system' in app.lower():
                emoji = "⚙️"
            else:
                emoji = "🖥️"
            self.apps_list.addItem(f'{emoji} {app}: {count}')

    def update_stats(self):
        if not self.sniffer_thread:
            return
        stats = self.sniffer_thread.get_stats()
        t = self.lang_widgets[self.lang]
        if stats['packets'] == 0:
            self.stats_text.setText(t['stats_no_data'])
            return
        elapsed = datetime.now() - stats['start_time'] if stats['start_time'] else datetime.now() - datetime.now()
        text = f"""
{t['stats_title']}
{t['stats_uptime']}: {str(elapsed).split('.')[0]}
{t['stats_packets']}: {stats['packets']}
{t['stats_domains']}: {stats['domains']}
{t['stats_connections']}: {stats['connections']}

{t['stats_protocols']}:
"""
        if stats['packet_counts']:
            for proto, count in sorted(stats['packet_counts'].items(), key=lambda x: x[1], reverse=True):
                bytes_count = stats['bytes_sent'].get(proto, 0)
                if bytes_count > 1024*1024:
                    size_str = f"{bytes_count/(1024*1024):.2f} MB"
                elif bytes_count > 1024:
                    size_str = f"{bytes_count/1024:.2f} KB"
                else:
                    size_str = f"{bytes_count} B"
                text += f"  {proto}: {count} packets, {size_str}\n"
        self.stats_text.setText(text)

    def update_time(self):
        if self.sniffer_thread and self.sniffer_thread.running:
            stats = self.sniffer_thread.get_stats()
            if stats['start_time']:
                elapsed = datetime.now() - stats['start_time']
                t = self.lang_widgets[self.lang]
                self.time_label.setText(f"{t['time']}: {str(elapsed).split('.')[0]}")

    def start_sniffing(self):
        self.log("Start button pressed")
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.log("Already running")
            return
        try:
            self.sniffer_thread = SnifferThread()
            self.sniffer_thread.dns_signal.connect(self.on_dns)
            self.sniffer_thread.tcp_signal.connect(self.on_tcp)
            self.sniffer_thread.stats_signal.connect(self.on_stats)
            self.sniffer_thread.error_signal.connect(self.on_error)
            self.sniffer_thread.log_signal.connect(self.log)
            self.sniffer_thread.finished_signal.connect(self.on_finished)
            self.sniffer_thread.start()
            t = self.lang_widgets[self.lang]
            self.status_label.setText(t['status_running'])
            self.status_label.setStyleSheet('font-size: 14px; font-weight: bold; color: #6bcb77;')
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.statusBar.showMessage(t['status_running_msg'])
            self.log("Sniffer started")
        except Exception as e:
            self.log(f"Error: {e}")

    def stop_sniffing(self):
        self.log("Stop button pressed")
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait(2000)
            self.sniffer_thread = None
        t = self.lang_widgets[self.lang]
        self.status_label.setText(t['status_stopped'])
        self.status_label.setStyleSheet('font-size: 14px; font-weight: bold; color: #ff6b6b;')
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar.showMessage(t['status_stopped_msg'])
        self.log("Sniffer stopped")

    def clear_data(self):
        self.log("Clearing data")
        self.dns_table.setRowCount(0)
        self.tcp_table.setRowCount(0)
        self.apps_list.clear()
        self.stats_text.clear()
        t = self.lang_widgets[self.lang]
        self.packets_label.setText(f"{t['packets']}: 0")
        self.domains_label.setText(f"{t['domains']}: 0")
        self.time_label.setText(f"{t['time']}: 00:00:00")
        self.statusBar.showMessage(t['status_cleared'])
        if self.sniffer_thread:
            stats = self.sniffer_thread.get_stats()
            self.packets_label.setText(f"{t['packets']}: {stats['packets']}")
            self.domains_label.setText(f"{t['domains']}: {stats['domains']}")

    def closeEvent(self, event):
        self.stop_sniffing()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setLayoutDirection(Qt.LeftToRight)
    window = SnifferGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
