# ADExplorerSnapshot.py

![Python 3.6+ compatible](https://img.shields.io/badge/python-%5E3.6-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

ADExplorerSnapshot.py is an AD Explorer snapshot ingestor for [BloodHound](https://bloodhound.readthedocs.io/).

## Limitations

The ingestor only supports offline information collection from the Snapshot file and won't interact with systems on the network. That means features like session and localadmin collection are not available. GPO/OU collection is missing. The ingestor processes all data it possibly can from the snapshot (including ACLs).

## Installation

```
git clone https://github.com/c3c/ADExplorerSnapshot.py.git
cd ADExplorerSnapshot.py
pip3 install --user .
```

## Usage

```
usage: ADExplorerSnapshot.py [-h] [-v] snapshot

ADExplorer snapshot ingestor for BloodHound

positional arguments:
  snapshot

optional arguments:
  -h, --help  show this help message and exit
  -v          Enable verbose output
```
