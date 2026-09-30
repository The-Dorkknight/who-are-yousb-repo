# How it works

> **Work in progress:** many features may be broken. This page describes the intended design.

## What it reads
- **sysfs** (`/sys/bus/usb/devices`, `/sys/class/typec`, `/sys/class/power_supply`, `/sys/class/net`): device names, speeds,
  descriptors, charger and cable information. Read-only.
- **usb.ids** (from the system, if present) to turn vendor/product numbers into names.
- **Kernel log** (`journalctl -k` / `dmesg`) in `monitor`, to recognise USB error messages. Needs permission on some systems.

## What it may change (only when you ask)
| Command | Change |
|---|---|
| `usb-net --assign` | Temporarily adds an IP address to the USB network interface to look for gadgets; removed afterwards unless `--keep` |
| `usb-net --android` | Asks a USB-debugging phone (via `adb`) to switch to USB tethering |
| `udev --install` | Writes one rule file under `/etc/udev/rules.d/` (asks for admin rights) |
| `capture` | Loads the kernel `usbmon` module and records traffic with `tcpdump`/`dumpcap` |
| Add to applications menu | Writes a `.desktop` file and icon under `~/.local/share` |

Nothing is uploaded anywhere. There is no telemetry and no network access except your own local USB-network links.

## Features
- **Snoop detection:** snapshots the USB tree, waits for you to plug the cable in, and flags everything that appears beyond the
  one expected device, plus high-risk classes (HID keyboard, network adapter, hidden hub) and odd descriptors.
- **Cable test:** compares the speed a known device reaches through the cable with what the device and port can do.
- **Monitor:** polls the USB tree and follows the kernel log for reconnect loops, speed drops and errors like `-71`.
- **Serial:** lists adapters (CH340, CP210x, FTDI…), stable paths, group membership, and competing services.
- **USB networking:** finds USB network interfaces, pings the IPv6 all-nodes address, sweeps a sensible IPv4 range (never larger than a /24), reads the neighbour table, and probes a few common ports.
- **Reverse engineering:** `capture` records usbmon traffic; `analyze` parses the pcap, decodes control transfers and the
  firmware download, infers the frame format (including hidden per-packet headers), carves embedded images (JPEG etc.),
  and searches for calibration data (camera matrices, stereo baselines, compressed blobs). `find-calib` does a file search.

## Limits
Heuristics, not guarantees. See "Known limitations" in the [README](README.md).
