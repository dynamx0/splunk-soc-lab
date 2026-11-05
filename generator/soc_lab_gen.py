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


def baseline_day(s, day):
    workday = day.weekday() < 5
    for user, (pc, ip_int, ip_pub, _) in USERS.items():
        if not workday and RNG.random() < 0.8:
            continue
        start = day.replace(hour=8, minute=0, second=0, microsecond=0) + timedelta(minutes=RNG.randint(0, 90))
        # Ouverture de session AD + eventuelle erreur de saisie isolee
        if RNG.random() < 0.15:
            win(s, start - timedelta(seconds=20), 4771, "DC01", Account_Name=user, src_ip=ip_int,
                Failure_Code="0x18", Message="Kerberos pre-authentication failed")
        win(s, start, 4624, "DC01", Account_Name=user, src_ip=ip_int, Logon_Type=3,
            Message="An account was successfully logged on")
        # Teletravail : connexion VPN depuis l'IP publique habituelle
        if RNG.random() < 0.45:
            vpn(s, start - timedelta(minutes=2), user, ip_pub, ok=True, ipv4=f"10.8.0.{RNG.randint(2, 250)}")
        # Activite sur le serveur de fichiers (evenement 5145)
        for _ in range(RNG.randint(5, 25)):
            t = start + timedelta(minutes=RNG.randint(0, 540))
            share = RNG.choice(SHARES)
            win(s, t, 5145, "SRV-FILE01", Account_Name=user, src_ip=ip_int, Share_Name=share,
                Relative_Target_Name=f"{share}\\{RNG.choice(SHARE_FILES)}", Accesses=RNG.choice(SHARE_ACTIONS),
                Message="A network share object was checked")
        # Navigation web + DNS
        for _ in range(RNG.randint(30, 80)):
            t = start + timedelta(seconds=RNG.randint(0, 9 * 3600))
            d = RNG.choice(LEGIT_DOMAINS)
            dns(s, t, ip_int, d)
            proxy(s, t + timedelta(milliseconds=150), ip_int, user,
                  f"https://{d}/{RNG.choice(['', 'index.html', 'api/v1/data', 'static/app.js'])}")
            fw(s, t, "pass", "out", ip_int, RNG.choice(["142.250.74.36", "13.107.42.14", "151.101.1.69"]), 443)
        # Processus courants (Sysmon)
        for _ in range(RNG.randint(10, 30)):
            t = start + timedelta(seconds=RNG.randint(0, 9 * 3600))
            img, h = RNG.choice(list(LEGIT_PROCS.items()))
            sysmon(s, t, 1, "Process Create", pc, Image=img, sha1=h, User=f"ARILAB\\{user}",
                   ParentImage=r"C:\Windows\explorer.exe", ParentCommandLine=r"C:\Windows\explorer.exe",
                   CommandLine=f'"{img}"')
        # Quelques creations de fichiers normales
        for _ in range(RNG.randint(3, 8)):
            t = start + timedelta(seconds=RNG.randint(0, 9 * 3600))
            sysmon(s, t, 11, "File Create", pc, Image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                   sha1=LEGIT_PROCS[r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"],
                   TargetFilename=f"C:\\Users\\{user}\\Documents\\doc_{RNG.randint(1, 999)}.docx",
                   ParentCommandLine=r"C:\Windows\explorer.exe")
    # Bruit Internet : paquets entrants bloques (scans opportunistes)
    for _ in range(RNG.randint(150, 300)):
        t = day + timedelta(seconds=RNG.randint(0, 86399))
        fw(s, t, "block", "in", RNG.choice(SCANNER_IPS + ["5.188.10.1", "92.63.197.5", "45.155.205.9"]),
           "198.18.0.10", RNG.choice([22, 23, 80, 443, 445, 1900, 3389, 8080]))
    # Scan Loki quotidien sur les serveurs (rien de trouve)
    for host in SERVERS:
        t = day.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(minutes=RNG.randint(0, 20))
        loki(s, t, host, "NOTICE", "Init", "Starting Loki Scan", 0)
        loki(s, t + timedelta(minutes=14), host, "RESULT", "Results",
             "SYSTEM SEEMS TO BE CLEAN.", 0)


def sc_vpn_impossible_travel(s, t):
    """Meme utilisateur VPN depuis deux lieux eloignes."""
    vpn(s, t, "alice.martin", USERS["alice.martin"][2], ok=True, ipv4="10.8.0.41")
    vpn(s, t + timedelta(minutes=25), "alice.martin", FOREIGN_IPS["BR"], ok=True, ipv4="10.8.0.42")


def sc_vpn_bruteforce(s, t):
    """Brute Force OpenVPN : echecs repetes depuis une meme IP."""
    for i, u in enumerate(["admin", "test", "lucas.bernard", "lucas.bernard", "vpn", "lucas.bernard",
                           "administrator", "lucas.bernard", "root", "lucas.bernard", "lucas.bernard", "support"]):
        vpn(s, t + timedelta(seconds=i * 7), u, FOREIGN_IPS["VN"], ok=False)


def sc_vpn_many_ips(s, t):
    """Utilisateur VPN avec plus de 3 IP en moins d'une heure."""
    for i, ip in enumerate([USERS["thomas.petit"][2], FOREIGN_IPS["DE"], FOREIGN_IPS["US"], "84.130.99.10"]):
        vpn(s, t + timedelta(minutes=i * 12), "thomas.petit", ip, ok=True, ipv4=f"10.8.0.{60 + i}")


def sc_ad_bruteforce(s, t, attacker_ip="10.128.0.99", account="nadia.rami", n=15):
    """Brute Force sur domaine Windows (EventCode 4771, plus de 3 en 5 min)."""
    for i in range(n):
        win(s, t + timedelta(seconds=i * 9), 4771, "DC01", Account_Name=account, src_ip=attacker_ip,
            Failure_Code="0x18", Message="Kerberos pre-authentication failed")


def sc_log_clear(s, t):
    """Effacement du journal de securite (EventCode 1102)."""
    win(s, t, 1102, "SRV-FILE01", Account_Name="adm.backup", src_ip="10.128.1.20",
        Message="The audit log was cleared")


def sc_service_install(s, t):
    """Service malveillant installe (EventCode 7045)."""
    win(s, t, 7045, "SRV-WEB01", Account_Name="LocalSystem", Service_Name="svc_tmp_runner",
        Service_File_Name=r"C:\Windows\Temp\svc_tmp_runner.exe", Service_Start_Type="auto start",
        Message="A service was installed in the system")


def sc_persistence_run_key(s, t):
    """Persistance : ecriture dans la cle Run (Sysmon 13) puis connexions vers un C&C."""
    pc = USERS["karim.benali"][0]
    sysmon(s, t, 1, "Process Create", pc, Image=PERSIST_IMAGE, sha1=PERSIST_SHA1,
           User="ARILAB\\karim.benali", ParentImage=r"C:\Windows\System32\cmd.exe",
           ParentCommandLine=r"C:\Windows\System32\cmd.exe", CommandLine=f'"{PERSIST_IMAGE}"')
    sysmon(s, t + timedelta(seconds=3), 13, "Registry value set", pc, Image=PERSIST_IMAGE, sha1=PERSIST_SHA1,
           TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WinUpdSvc",
           Details=PERSIST_IMAGE, EventType="SetValue")
    for i in range(6):
        sysmon(s, t + timedelta(minutes=5 * i + 1), 3, "Network connection detected", pc, Image=PERSIST_IMAGE,
               sha1=PERSIST_SHA1, DestinationIp=BAD_IP, DestinationPort=443, Protocol="tcp")
        fw(s, t + timedelta(minutes=5 * i + 1), "pass", "out", USERS["karim.benali"][1], BAD_IP, 443,
           bytes_=RNG.randint(20000, 400000))


def sc_ransomware(s, t):
    """Ransomware : processus inconnu qui cree plus de 10 fichiers en 1 minute (Sysmon 11)."""
    user = "sophie.durand"
    pc = USERS[user][0]
    sysmon(s, t, 1, "Process Create", pc, Image=SUSPECT_IMAGE, sha1=SUSPECT_SHA1, User=f"ARILAB\\{user}",
           ParentImage=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
           ParentCommandLine=r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
           CommandLine=f'"{SUSPECT_IMAGE}"')
    for i in range(45):
        sysmon(s, t + timedelta(seconds=5 + i), 11, "File Create", pc, Image=SUSPECT_IMAGE, sha1=SUSPECT_SHA1,
               TargetFilename=f"C:\\Users\\{user}\\Documents\\{RNG.choice(SHARE_FILES)}.{i}.locked",
               ParentCommandLine=r'"C:\Program Files\Google\Chrome\Application\chrome.exe"')


def sc_false_positive_unzip(s, t):
    """Faux positif volontaire : 7-Zip extrait 30 fichiers (hash dans la liste blanche)."""
    user = "lucas.bernard"
    pc = USERS[user][0]
    img = r"C:\Program Files\7-Zip\7z.exe"
    for i in range(30):
        sysmon(s, t + timedelta(seconds=i), 11, "File Create", pc, Image=img, sha1=LEGIT_PROCS[img],
               TargetFilename=f"C:\\Users\\{user}\\Downloads\\archive\\file_{i:03d}.csv",
               ParentCommandLine=r"C:\Windows\explorer.exe")


def sc_malware_delivery(s, t):
    """Livraison de malware : telechargement d'un executable puis rafale de requetes."""
    user = "sophie.durand"
    ip = USERS[user][1]
    proxy(s, t, ip, user, "http://files.badlab.example/download/facture_2024.pdf.exe", bytes_=482113)
    for i in range(25):
        proxy(s, t + timedelta(seconds=2 + i * 0.8), ip, user,
              f"http://{BAD_DOMAIN}/gate.php?id={RNG.randint(1000, 9999)}", bytes_=RNG.randint(200, 900))


def sc_dns_anomaly(s, t):
    """Activite DNS inhabituelle : volume eleve de requetes de meme taille."""
    ip = USERS["sophie.durand"][1]
    for i in range(400):
        label = "".join(RNG.choice("0123456789abcdef") for _ in range(32))
        dns(s, t + timedelta(seconds=i * 3), ip, f"{label}.{BAD_DOMAIN}", qtype="TXT")


def sc_port_scan_internal(s, t):
    """Scan de ports interne : un poste interne touche de nombreux ports."""
    src = "10.128.0.99"
    for i, port in enumerate(list(range(20, 140)) + [443, 445, 1433, 3306, 3389, 5985, 8080, 8443]):
        fw(s, t + timedelta(milliseconds=i * 120), "block", "in", src, SERVERS["SRV-WEB01"], port,
           fw_name="fw-internal", bytes_=60)


def sc_loki_detection(s, t):
    """Loki detecte un IOC (hash) et une connexion C&C sur SRV-FILE01."""
    host = "SRV-FILE01"
    loki(s, t, host, "NOTICE", "Init", "Starting Loki Scan", 0)
    loki(s, t + timedelta(minutes=3), host, "ALERT", "FileScan", "Malicious file found", 135,
         file=r"C:\ProgramData\cache\winupdsvc.exe", sha1=PERSIST_SHA1,
         reason="Hash IOC match - OTX feed (lab)")
    loki(s, t + timedelta(minutes=4), host, "WARNING", "FileScan", "Suspicious file name", 70,
         file=r"C:\Windows\Temp\svc_tmp_runner.exe", reason="Filename IOC match (lab)")
    loki(s, t + timedelta(minutes=6), host, "ALERT", "ProcessScan", "C2 connection detected", 120,
         remote_ip=BAD_IP, reason="C2 IOC match - OTX feed (lab)")
    loki(s, t + timedelta(minutes=14), host, "RESULT", "Results", "Indicators detected!", 0)


SCENARIOS = {
    # nom : (fonction, decalage par rapport a maintenant pour l'historique)
    "vpn_impossible_travel": (sc_vpn_impossible_travel, timedelta(days=2, hours=3)),
    "vpn_bruteforce":        (sc_vpn_bruteforce,        timedelta(days=1, hours=20)),
    "vpn_many_ips":          (sc_vpn_many_ips,          timedelta(days=1, hours=6)),
    "bruteforce_ad":         (sc_ad_bruteforce,         timedelta(days=1, hours=2)),
    "log_clear":             (sc_log_clear,             timedelta(hours=26)),
    "persistence_run_key":   (sc_persistence_run_key,   timedelta(hours=28)),
    "service_install":       (sc_service_install,       timedelta(hours=27)),
    "malware_delivery":      (sc_malware_delivery,      timedelta(hours=22)),
    "ransomware":            (sc_ransomware,            timedelta(hours=21, minutes=55)),
    "false_positive_unzip":  (sc_false_positive_unzip,  timedelta(hours=20)),
    "dns_anomaly":           (sc_dns_anomaly,           timedelta(hours=18)),
    "port_scan_internal":    (sc_port_scan_internal,    timedelta(hours=10)),
    "loki_detection":        (sc_loki_detection,        timedelta(hours=7)),
}


def cmd_history(args):
    s = Sink(args.out, append=False)
    now = datetime.now(TZ)
    first = (now - timedelta(days=args.days)).replace(hour=0, minute=0, second=0, microsecond=0)
    day = first
    while day < now:
        baseline_day(s, day)
        day += timedelta(days=1)
    # On ne garde pas d'evenements dans le futur
    for k in list(s.buf):
        s.buf[k] = [r for r in s.buf[k] if r[0] <= now]
    for name, (fn, delta) in SCENARIOS.items():
        fn(s, now - delta)
    counts = s.flush()
    print(f"Historique genere ({args.days} jours) dans {os.path.abspath(args.out)}")
    for k, v in sorted(counts.items()):
        print(f"  {k:<28} {v:>7} evenements")


def cmd_live(args):
    if args.scenario not in SCENARIOS:
        raise SystemExit(f"Scenario inconnu : {args.scenario}. Voir : list")
    s = Sink(args.out, append=True)
    SCENARIOS[args.scenario][0](s, datetime.now(TZ))
    counts = s.flush()
    print(f"Scenario '{args.scenario}' injecte maintenant : {counts}")


def cmd_list(_):
    for name, (fn, _) in SCENARIOS.items():
        print(f"  {name:<24} {fn.__doc__.strip().splitlines()[0]}")


def main():
    default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
    p = argparse.ArgumentParser(description="Generateur de logs synthetiques pour le lab SOC Splunk")
    sub = p.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("history", help="Genere l'historique + tous les scenarios")
    h.add_argument("--days", type=int, default=7)
    h.add_argument("--out", default=default_out)
    h.set_defaults(func=cmd_history)
    lv = sub.add_parser("live", help="Injecte un scenario a l'heure actuelle")
    lv.add_argument("--scenario", required=True)
    lv.add_argument("--out", default=default_out)
    lv.set_defaults(func=cmd_live)
    ls = sub.add_parser("list", help="Liste les scenarios")
    ls.set_defaults(func=cmd_list)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
