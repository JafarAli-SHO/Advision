

# Advision Tool

Advision is a Python-based tool for **LDAP and Active Directory enumeration**. It also includes features for testing connectivity, retrieving security policies, and identifying misconfigurations in enterprise environments. This tool is designed for **red teamers**, **penetration testers**, and **cybersecurity professionals**.

![advision](https://github.com/user-attachments/assets/b26ab55f-a3b6-4091-911e-06ac211de8f6)



---

## Features

- **LDAP Enumeration** (users, schema, Active Directory hierarchy)
- **Group Policy Objects (GPOs)** enumeration
- **SMB and DCOM** connectivity tests
- **Domain Password Policy** retrieval
- **DNS Misconfiguration** checks
- **SID History** retrieval
- **PDF Report Generation** for findings

---

## Requirements

Before running the tool, ensure you have the following installed:

- **Python 3.7 or higher**
- Required Python libraries:
  - `ldap3`
  - `colorama`
  - `pyfiglet`
  - `argparse`
  - `fpdf`
  - `winrm`
  - `smbprotocol`
  - `dnspython`
  - `impacket`

You can install all dependencies using:
```bash
pip install -r requirements.txt
```

---

## Usage

Run the tool from the terminal using the following command format:
```bash
python Advision.py --server <LDAP_SERVER_IP> --domain <DOMAIN> --username <USERNAME> --password <PASSWORD> [OPTIONS]
```

---

### Common Options

| Option                | Description                                                                                  |
|-----------------------|----------------------------------------------------------------------------------------------|
| `-ip`, `--server`     | IP address of the LDAP server.                                                               |
| `-d`, `--domain`      | The domain for NTLM authentication.                                                         |
| `-u`, `--username`    | Username for NTLM authentication.                                                           |
| `-P`, `--password`    | Password for NTLM authentication.                                                           |
| `-pwp`                | Retrieve the domain password policy.                                                        |
| `-H`                  | Retrieve the Active Directory hierarchy.                                                    |
| `--schema`            | Retrieve LDAP schema information.                                                           |
| `-f`, `--filter`      | Filter options for LDAP enumeration (`all` or `users`).                                      |
| `--gpo`               | Enumerate Group Policy Objects (GPOs).                                                      |
| `--dns`               | Check DNS misconfigurations.                                                                |
| `--smb`               | Test SMB connectivity and enumerate shares.                                                 |
| `--dcom`              | Test DCOM connectivity.                                                                     |
| `--sidhistory`        | Retrieve SID history for a specified user.                                                  |

---

### Example Commands

#### 1. **Enumerate all LDAP users:**
```bash
python Advision.py -ip 192.168.1.10 -d domain.local -u admin -P password -f users
```

#### 2. **Retrieve Active Directory hierarchy:**
```bash
python Advision.py -ip 192.168.1.10 -d domain.local -u admin -P password -H
```

#### 3. **Check DNS misconfigurations:**
```bash
python Advision.py --server 192.168.1.10 --dns
```

---

## Outputs

The tool generates a detailed PDF report for LDAP enumeration results, saved as:
```bash
ldapenumerationresults.pdf
```
in the current directory.

---
