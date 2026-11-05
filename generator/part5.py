

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
