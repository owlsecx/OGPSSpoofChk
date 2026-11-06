# 🦉 OGPSSpoofChk

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Wireless%20/%20RF-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OGPSSpoofChk** — GPS/GNSS spoofing detector — offline NMEA/pcap analysis (teleport, C/N0, timing) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OGPSSpoofChk — GPS/GNSS spoofing detector — offline NMEA/pcap analysis (teleport, C/N0, timing). GPS Spoofing Detector OWL Security Tools · Batch 3 (Wireless) This tool performs OFFLINE analysis of wireless protocol artifacts (pcap, hex, CSV, IQ, NMEA, LDIF-style captures). It never touches a live radio.

---

## ✨ Features

- Offline GPS/GNSS spoofing detection from NMEA or pcap
- Teleport, C/N0 and timing anomaly heuristics
- Correlate jumps that break physical motion constraints
- Lab-friendly analysis without live RF gear required
- Graded findings for investigator review
- Export reports for DFIR notes

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OGPSSpoofChk OGPSSpoofChk.go
./OGPSSpoofChk --help
./OGPSSpoofChk --input track.nmea
./OGPSSpoofChk --input gnss.pcap --format json
./OGPSSpoofChk --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
