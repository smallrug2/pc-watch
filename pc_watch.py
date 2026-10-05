"""pc_watch.py - Cross-platform overnight system sentinel.

Purpose: take periodic system snapshots (processes, listeners/ports,
    autoruns hash, canary tripwire files, hosts-file hash, USB list,
    thermals, Defender state on Windows) into CSV logs. Baselines on the
    first cycle and notes changes. Stops when a STOP.txt file appears in
    --outdir, or use --once for a single snapshot.

Usage:
    python pc_watch.py --interval 60 --outdir ./watch-logs
    python pc_watch.py --once --outdir ./watch-logs
    python pc_watch.py --interval 30 --canary-dir ./canaries

Platform: Windows + Linux. psutil is optional but recommended:
    pip install psutil
    Without psutil the script falls back to stdlib/platform shims and
    prints a clear SKIP for features unavailable on the OS (never crashes).
"""
import argparse
import csv
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False

CANARY_NAMES = ["~$invoice_2024.docx", "~$passwords_backup.txt",
                "~$tax_return_2025.pdf"]


def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short_hash(s):
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:16]


def sha1_file(path):
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()[:16]
    except FileNotFoundError:
        return "MISSING"
    except OSError:
        return "UNREADABLE"


def hosts_path():
    if os.name == "nt":
        return Path(r"C:\Windows\System32\drivers\etc\hosts")
    return Path("/etc/hosts")


def log_csv(path, row):
    """Append row dict to CSV, writing a header on first creation."""
    path = Path(path)
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp"] + list(row.keys()))
        if new:
            w.writeheader()
        w.writerow({"timestamp": ts(), **row})


def alert(outdir, level, msg):
    log_csv(Path(outdir) / "alerts.csv", {"level": level, "msg": msg[:600]})
    print("[%s] %s" % (level, msg[:200]))


# ---- collectors (psutil first, stdlib shims after) ----

def get_processes():
    if HAS_PSUTIL:
        try:
            names = sorted({p.info.get("name") or "?"
                            for p in psutil.process_iter(["name"])})
            return " ".join(names)
        except Exception as e:
            return "ERR:%s" % e
    if os.name == "nt":  # fallback: tasklist
        try:
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                               capture_output=True, text=True, timeout=60)
            return " ".join(sorted({l.split(",")[0].strip('"') for l in
                                    r.stdout.splitlines() if l.strip()}))
        except Exception as e:
            return "ERR:%s" % e
    try:  # Linux: /proc
        names = []
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    with open("/proc/%s/comm" % pid, encoding="utf-8",
                              errors="ignore") as f:
                        names.append(f.read().strip())
                except OSError:
                    pass
        return " ".join(sorted(set(names)))
    except OSError:
        pass  # no /proc (e.g. macOS) -> fall through to ps
    try:  # macOS and other Unix: ps
        r = subprocess.run(["ps", "-eo", "comm="],
                           capture_output=True, text=True, timeout=60)
        return " ".join(sorted({l.strip() for l in
                                r.stdout.splitlines() if l.strip()}))
    except Exception as e:
        return "ERR:%s" % e


def get_listeners():
    if HAS_PSUTIL:
        try:
            ports = sorted({c.laddr.port for c in psutil.net_connections("tcp")
                            if c.status == "LISTEN" and c.laddr})
            return " ".join(map(str, ports))
        except Exception as e:
            return "ERR:%s" % e
    print("SKIP: listeners need psutil on this OS")
    return "SKIP:no-psutil"


def get_net_summary():
    if HAS_PSUTIL:
        try:
            seen = set()
            for c in psutil.net_connections("tcp"):
                if getattr(c.status, "upper", lambda: "")() == "ESTABLISHED" \
                        and c.raddr:
                    try:
                        pname = psutil.Process(c.pid).name() if c.pid else "?"
                    except Exception:
                        pname = "?"
                    seen.add("%s %s:%s" % (pname, c.raddr.ip, c.raddr.port))
            return " | ".join(sorted(seen))[:3000] or "(none)"
        except Exception as e:
            return "ERR:%s" % e
    print("SKIP: established connections need psutil on this OS")
    return "SKIP:no-psutil"


def get_temps():
    if HAS_PSUTIL:
        try:
            temps = psutil.sensors_temperatures()
            if not temps:
                print("SKIP: no temperature sensors reported on this OS")
                return "SKIP:no-sensors"
            bits = []
            for name, entries in temps.items():
                for e in entries:
                    bits.append("%s=%s" % (e.label or name, e.current))
            return ",".join(bits)[:300]
        except Exception as e:
            return "ERR:%s" % e
    # nvidia-smi shim (optional, GPU only)
    if shutil.which("nvidia-smi"):
        try:
            r = subprocess.run(["nvidia-smi",
                                "--query-gpu=temperature.gpu",
                                "--format=csv,noheader"],
                               capture_output=True, text=True, timeout=30)
            return "gpu=%s" % r.stdout.strip().replace("\n", "|")
        except Exception as e:
            return "ERR:%s" % e
    print("SKIP: thermals need psutil (or nvidia-smi)")
    return "SKIP:no-psutil"


def get_usb():
    if os.name == "nt":
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command",
                                "Get-PnpDevice -Class USB -EA SilentlyContinue"
                                " | Where-Object {$_.Status -eq 'OK'} | "
                                "Select-Object -Expand FriendlyName | "
                                "Sort-Object -Unique"],
                               capture_output=True, text=True, timeout=90)
            return r.stdout.strip().replace("\n", "|")[:300]
        except Exception as e:
            return "ERR:%s" % e
    # Linux: enumerate /sys/bus/usb product names.
    try:
        base = Path("/sys/bus/usb/devices")
        if not base.is_dir():
            print("SKIP: USB enumeration not supported on this OS")
            return "SKIP:unsupported"
        names = []
        for dev in base.iterdir():
            prod = dev / "product"
            try:
                if prod.is_file():
                    names.append(prod.read_text(
                        encoding="utf-8", errors="ignore").strip())
            except OSError:
                pass
        return "|".join(sorted(set(names)))[:300] or "(none)"
    except Exception as e:
        return "ERR:%s" % e


def get_defender():
    if os.name != "nt":
        print("SKIP: Defender state is Windows-only")
        return "SKIP:windows-only"
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "(Get-MpComputerStatus -EA SilentlyContinue)."
                            "RealTimeProtectionEnabled"],
                           capture_output=True, text=True, timeout=60)
        out = r.stdout.strip()
        return out if out else "SKIP:defender-unavailable"
    except Exception as e:
        return "ERR:%s" % e


def autoruns_snapshot():
    """Return a string describing persistence points; hashed by caller."""
    if os.name == "nt":
        # Registry Run keys (winreg) + startup folder listing.
        bits = []
        try:
            import winreg
            for hive, sub in (
                    (winreg.HKEY_CURRENT_USER,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")):
                try:
                    with winreg.OpenKey(hive, sub) as k:
                        for i in range(winreg.QueryInfoKey(k)[1]):
                            n, v, _ = winreg.EnumValue(k, i)
                            bits.append("%s=%s" % (n, v))
                except OSError:
                    pass
        except ImportError:
            bits.append("winreg-unavailable")
        try:
            startup = (Path(os.environ.get("APPDATA", "")) /
                       "Microsoft/Windows/Start Menu/Programs/Startup")
            if startup.is_dir():
                bits += sorted(p.name for p in startup.iterdir())
        except OSError:
            pass
        return "|||".join(bits)
    # Linux: autostart dirs + crontab listing (best effort).
    bits = []
    for d in (Path.home() / ".config/autostart", Path("/etc/xdg/autostart")):
        try:
            if d.is_dir():
                bits += sorted(p.name for p in d.iterdir())
        except OSError:
            pass
    return "|||".join(bits) or "(none)"


def plant_canaries(canary_dir):
    canary_dir = Path(canary_dir)
    canary_dir.mkdir(parents=True, exist_ok=True)
    for c in CANARY_NAMES:
        p = canary_dir / c
        if not p.exists():
            p.write_text("tripwire file - do not delete - %s\n" % ts(),
                         encoding="utf-8")


def check_canaries(canary_dir):
    tripped = []
    for c in CANARY_NAMES:
        if not (Path(canary_dir) / c).exists():
            tripped.append(c + ":GONE")
    return tripped


def snapshot_once(outdir, canary_dir):
    """Collect one snapshot dict (values are short strings)."""
    hosts = sha1_file(str(hosts_path()))
    can = check_canaries(canary_dir)
    row = {
        "procs_n": str(len(get_processes().split())),
        "listeners": get_listeners()[:300],
        "net": get_net_summary()[:800],
        "defender": get_defender()[:100],
        "autoruns_hash": short_hash(autoruns_snapshot()),
        "canary": ",".join(can) or "ok",
        "hosts": hosts,
        "usb": get_usb()[:300],
        "thermals": get_temps()[:300],
    }
    log_csv(Path(outdir) / "snapshot.csv", row)
    return row


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Cross-platform system sentinel")
    p.add_argument("--interval", type=int, default=60,
                   help="Seconds between snapshots")
    p.add_argument("--outdir", default=str(Path.cwd() / "watch-logs"),
                   help="Directory for CSV logs and STOP.txt")
    p.add_argument("--canary-dir",
                   default=str(Path.home() / "Documents"),
                   help="Directory holding canary tripwire files")
    p.add_argument("--once", action="store_true",
                   help="Take a single snapshot and exit")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if not HAS_PSUTIL:
        print("NOTE: psutil not installed; using stdlib fallbacks "
              "(pip install psutil for full detail)")
    plant_canaries(args.canary_dir)
    base = snapshot_once(outdir, args.canary_dir) if not args.once else None
    if args.once:
        row = snapshot_once(outdir, args.canary_dir)
        for k, v in row.items():
            print("%s: %s" % (k, v[:200]))
        return
    alert(outdir, "INFO", "pc_watch started (interval=%ss)" % args.interval)
    base_procs, base_listen = get_processes(), base["listeners"]
    base_hosts, base_auto = base["hosts"], base["autoruns_hash"]
    while True:
        if (outdir / "STOP.txt").exists():
            alert(outdir, "INFO", "STOP.txt found, exiting")
            return
        try:
            row = snapshot_once(outdir, args.canary_dir)
            procs = get_processes()
            new_p = [x for x in procs.split()
                     if x not in base_procs.split()]
            if new_p:
                alert(outdir, "PROC", "new: " + ",".join(new_p[:12]))
                base_procs = procs
            if row["listeners"] != base_listen:
                alert(outdir, "NET",
                      "listeners changed: " + row["listeners"][:300])
                base_listen = row["listeners"]
            if row["canary"] != "ok":
                alert(outdir, "CRITICAL", "CANARY TRIPPED: " + row["canary"])
            if row["hosts"] != base_hosts:
                alert(outdir, "ALERT", "hosts file changed!")
            if row["autoruns_hash"] != base_auto:
                alert(outdir, "ALERT", "autoruns changed")
                base_auto = row["autoruns_hash"]
            if "False" in row["defender"]:
                alert(outdir, "ALERT", "Defender RTP OFF")
        except Exception as ex:  # never crash the loop
            alert(outdir, "ERR", str(ex)[:200])
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    main()
