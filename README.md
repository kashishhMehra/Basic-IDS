# Basic-IDS 🔍

So I built this small IDS (Intrusion Detection System) in Python as a way to learn how network packets actually work under the hood. It's just ~30 lines of code, but it genuinely sniffs real network traffic and can flag suspicious activity.

## What it does
It sits quietly in the background, listening to all network packets passing through your machine. The moment it spots something suspicious in the packet data — like a dodgy domain or unauthorized access attempt — it calls it out.

## How I built it
I used Python's raw socket interface (`AF_PACKET`) which lets you capture packets right at the data link layer, before any filtering happens. Each packet gets its Ethernet header stripped and parsed using the `struct` module, and then the payload is scanned for any patterns I've flagged as suspicious.
I took help from youtube videos as well, this was my first cybersecurity project as a beginner so i understood a lot of things and then wrote this code with the help of different videos, hence the comments in my code.
## Requirements
- Linux (I used Kali Linux)
- Python 3
- sudo privileges — raw sockets need root access

## How to run it
```bash
sudo python3 ids.py
```

Then just let it run. Open a browser, ping something, browse around — it'll start capturing packets. If anything matches your suspicious patterns, it'll print an alert.

## Customising the patterns
You can add whatever patterns you want to watch for:
```python
sus_patterns = ['danger.com', 'unauthorized_access']
```
Any packet payload containing these strings will trigger an alert.

## What I learned
- How Ethernet frames are actually structured (6+6+2 bytes)
- Raw socket programming in Python
- How to parse binary network data with `struct`
- Why network byte order (big-endian) matters
- The basics of how real IDS tools work at a low level

## Disclaimer
Built for learning purposes only. Only run this on networks you own or have permission to monitor.
