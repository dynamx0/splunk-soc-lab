

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
