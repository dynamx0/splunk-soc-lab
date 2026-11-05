#!/usr/bin/env python3
"""Generateur de logs SYNTHETIQUES pour le lab SOC Splunk."""
import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=2))  # Europe/Paris (heure d'ete)
RNG = random.Random(2017)

# Utilisateurs fictifs : poste, IP interne, IP publique habituelle, pays
USERS = {
    "alice.martin":   ("PC-001", "10.128.0.21", "90.84.10.21",  "FR"),
    "karim.benali":   ("PC-002", "10.128.0.22", "82.64.33.17",  "FR"),
    "sophie.durand":  ("PC-003", "10.128.0.23", "86.200.14.9",  "FR"),
    "yassine.haddad": ("PC-004", "10.128.0.24", "41.226.11.40", "TN"),
    "lucas.bernard":  ("PC-005", "10.128.0.25", "78.192.77.3",  "FR"),
    "nadia.rami":     ("PC-006", "10.128.0.26", "90.84.200.5",  "FR"),
    "thomas.petit":   ("PC-007", "10.128.0.27", "82.64.150.66", "FR"),
    "ines.lefevre":   ("PC-008", "10.128.0.28", "86.200.90.12", "FR"),
}
SERVERS = {"DC01": "10.128.1.10", "SRV-FILE01": "10.128.1.20", "SRV-WEB01": "10.128.2.10"}
SHARES = [r"\\*\Donnees utilisateurs", r"\\*\SI AriLab", r"\\*\Projets", r"\\*\Echanges", r"\\*\Directions"]
SHARE_FILES = ["Rapport_Q3.docx", "Budget.xlsx", "Planning.pptx", "Procedure_SOC.pdf", "Notes.txt"]
SHARE_ACTIONS = ["READ_CONTROL", "SYNCHRONIZE", "ReadAttributes", "WriteData", "DELETE"]

# IP publiques etrangeres pour les scenarios, et scanners Internet
FOREIGN_IPS = {"BR": "177.43.80.12", "VN": "113.161.44.7", "US": "24.6.120.33", "DE": "84.130.21.9"}
SCANNER_IPS = ["61.160.224.161", "119.84.122.92", "194.170.74.182", "185.220.101.4", "45.95.147.20"]

# Processus legitimes (hash SHA1 FICTIFS), presents dans la liste blanche
LEGIT_PROCS = {
    r"C:\Program Files\Google\Chrome\Application\chrome.exe": "98A9A1C6F6937B211E5F1E303BA8762F44BC8981",
    r"C:\Windows\System32\svchost.exe": "4AF001B3C3816B860660CF2DE2C0FD3C1DFB4878",
    r"C:\Windows\explorer.exe": "7C1A5E2B9D0F3E4A6B8C1D2E3F405162738495A6",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE": "1B2C3D4E5F60718293A4B5C6D7E8F90112233445",
    r"C:\Program Files\7-Zip\7z.exe": "0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8091",
    r"C:\Windows\System32\cmd.exe": "F1E2D3C4B5A69788796A5B4C3D2E1F0A9B8C7D6E",
}
# Processus des scenarios d'attaque : NON presents dans la liste blanche
SUSPECT_IMAGE = r"C:\Users\sophie.durand\Downloads\facture_2024.pdf.exe"
SUSPECT_SHA1 = "DEADBEEF00112233445566778899AABBCCDDEEFF"
PERSIST_IMAGE = r"C:\Users\karim.benali\AppData\Roaming\winupdsvc.exe"
PERSIST_SHA1 = "C0FFEE0011223344556677889900AABBCCDDEE11"

LEGIT_DOMAINS = ["www.google.com", "outlook.office365.com", "teams.microsoft.com", "www.lemonde.fr",
                 "github.com", "www.linkedin.com", "update.microsoft.com", "cdn.jsdelivr.net"]
BAD_DOMAIN = "cdn-sync.badlab.example"  # domaine "C&C" fictif
BAD_IP = "203.0.113.66"                 # IP de documentation (RFC 5737)


def ts(dt):
    return dt.astimezone(TZ).isoformat(timespec="milliseconds")


class Sink:
    """Collecte les evenements par fichier puis les ecrit tries par date."""

    def __init__(self, out, append=False):
        self.out = out
        self.append = append
        self.buf = {}
        os.makedirs(out, exist_ok=True)

    def add(self, fname, dt, line):
        self.buf.setdefault(fname, []).append((dt, line))

    def flush(self):
        for fname, rows in self.buf.items():
            rows.sort(key=lambda r: r[0])
            mode = "a" if self.append else "w"
            with open(os.path.join(self.out, fname), mode, encoding="utf-8") as f:
                for _, line in rows:
                    f.write(line + "\n")
        counts = {k: len(v) for k, v in self.buf.items()}
        self.buf = {}
        return counts


def vpn(s, dt, user, src_ip, ok=True, ipv4=None):
    port = RNG.randint(1025, 65000)
    if ok:
        line = (f'{ts(dt)} athena openvpn[{RNG.randint(1000, 9999)}]: user={user} src_ip={src_ip} '
                f'src_port={port} IPv4={ipv4} action=success msg="Peer Connection Initiated"')
    else:
        line = (f'{ts(dt)} athena openvpn[{RNG.randint(1000, 9999)}]: user={user} src_ip={src_ip} '
                f'src_port={port} action=failure msg="AUTH_FAILED"')
    s.add("fw_vpn.log", dt, line)


def fw(s, dt, action, direction, src_ip, dst_ip, dst_port, proto="tcp", fw_name="fw-athena", bytes_=None):
    b = bytes_ if bytes_ is not None else RNG.randint(60, 15000)
    s.add("firewall.log", dt,
          f"{ts(dt)} {fw_name} filterlog: action={action} direction={direction} proto={proto} "
          f"src_ip={src_ip} src_port={RNG.randint(1025, 65000)} dst_ip={dst_ip} dst_port={dst_port} bytes={b}")


def win(s, dt, code, computer, **kv):
    fields = " ".join(f'{k}="{v}"' if " " in str(v) or "\\" in str(v) else f"{k}={v}" for k, v in kv.items())
    s.add("wineventlog_security.log", dt, f"{ts(dt)} ComputerName={computer} EventCode={code} {fields}")


def sysmon(s, dt, code, desc, computer, **kv):
    ev = {"time": ts(dt), "EventCode": code, "EventDescription": desc, "Computer": computer}
    ev.update(kv)
    s.add("sysmon.json", dt, json.dumps(ev, ensure_ascii=False))


def dns(s, dt, client, query, qtype="A", rcode="NOERROR"):
    s.add("dns.log", dt, f"{ts(dt)} dns01 named: client_ip={client} query={query} qtype={qtype} rcode={rcode}")


def proxy(s, dt, clientip, user, url, status=200, bytes_=None):
    fname = url.rsplit("/", 1)[-1] if "/" in url.split("://", 1)[-1] else "-"
    b = bytes_ if bytes_ is not None else RNG.randint(300, 90000)
    s.add("proxy.log", dt,
          f'{ts(dt)} proxy01 squid: clientip={clientip} user={user} method=GET url="{url}" '
          f'file="{fname}" status={status} bytes={b}')


def loki(s, dt, host, level, module, message, score=0, **kv):
    extra = " ".join(f'{k}="{v}"' for k, v in kv.items())
    s.add("loki.log", dt, f'{ts(dt)} {host} LOKI: level={level} module={module} score={score} '
                          f'message="{message}" {extra}'.rstrip())
