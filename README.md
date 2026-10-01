# NETUI

A Python/curses terminal network scanner for Linux.

## Requirements
- Python 3.9+
- `ping` (iputils)
- `ip` (iproute2)
- Optional: `smbclient` for enumerating SMB shares

On Arch Linux:
```bash
sudo pacman -S python iputils iproute2 smbclient
```
On Debian/Ubuntu:
```bash
sudo apt install python3 iputils-ping iproute2 smbclient
```

## Run
```bash
python3 netui.py
```

## Commands
- `:range 192.168.1.0/24` — scan an IPv4 network (up to 4096 addresses)
- `:range 192.168.1.10-192.168.1.80` — scan an address range
- `:ports 192.168.1.1` — scan TCP ports 1–1024 and selected common high ports
- `:portsUDP 192.168.1.1` — probe common UDP service ports (silent responses are shown as `OPEN|FILTERED`; this is a UDP scanning limitation)
- `:help` — show command help
- `:clear` — clear current results
- `:q` — quit
- `netui uninstall` — remove the installed NETUI launcher (does not delete user data)

## Keys
- `:` command mode
- `/` filter by IP or hostname
- `Ctrl+S` toggle online-first sorting
- `gg` jump to first row
- `G` jump to last row
- Up/Down or `j`/`k` navigate
- `Esc` close command/search mode

Results update as hosts finish scanning. The interface uses only the Python standard library; SMB enumeration uses `smbclient` when installed.
