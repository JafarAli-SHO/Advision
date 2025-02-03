**Features**
LDAP Enumeration (users, schema, Active Directory hierarchy)
Group Policy Objects (GPOs) enumeration
SMB and DCOM connectivity tests
Domain Password Policy retrieval
DNS Misconfiguration checks
SID History retrieval
PDF report generation for findings
**Requirements**
Before running the tool, ensure you have the following installed:

Python 3.7 or higher
Required Python libraries:
ldap3
colorama
pyfiglet
argparse
fpdf
winrm
smbprotocol
dnspython
impacket
You can install all dependencies using:
pip install -r requirements.txt
**Usage**
Run the tool from the terminal using the following command format:
python Advision.py --server <LDAP_SERVER_IP> --domain <DOMAIN> --username <USERNAME> --password <PASSWORD> [OPTIONS]
Common Options
-ip / --server: IP address of the LDAP server.
-d / --domain: The domain for NTLM authentication.
-u / --username: Username for NTLM authentication.
-P / --password: Password for NTLM authentication.
-pwp: Retrieve the domain password policy.
-H: Retrieve the Active Directory hierarchy.
--schema: Retrieve LDAP schema information.
-f / --filter: Filter options for LDAP enumeration (all or users).
--gpo: Enumerate Group Policy Objects (GPOs).
--dns: Check DNS misconfigurations.
--smb: Test SMB connectivity and enumerate shares.
--dcom: Test DCOM connectivity.
--sidhistory: Retrieve SID history for a specified user
