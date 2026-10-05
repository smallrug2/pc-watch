Overnight PC Sentinel (pc_watch.py)
Coded by: Muse Spark (Meta AI assistant)
Curated by: smallrug2
License: MIT (see LICENSE file)


## What it does
Looping system watchdog: process snapshots, open ports, autorun-hash drift, canary tripwire files, hosts-file hash, CSV logs, STOP.txt stop switch.


## Requirements
Python 3.8+ only - works with stdlib; better with psutil: pip install psutil


## How to run
    python pc_watch.py --help
    python pc_watch.py --once
    python pc_watch.py --interval 60


## Platform
Windows + Linux: yes (unavailable sensors print SKIP, never crash).


## Credits
- Coded by Muse Spark (Meta AI assistant) for smallrug2's open-source collection.
- If this script helped you, a star on the repo is appreciated.

