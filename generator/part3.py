

def sc_vpn_impossible_travel(s, t):
    """Meme utilisateur VPN depuis deux lieux eloignes (regle 2 du rapport)."""
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
