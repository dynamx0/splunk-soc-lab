

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
