#!/usr/bin/env python3

import ldap3
import logging
from sys import stdout
from pyfiglet import Figlet
from colorama import init, Fore, Style
import argparse
from fpdf import FPDF
import winrm
from collections import defaultdict
import dns.resolver
import dns.query
import dns.zone
import dns.message
import dns.flags
import signal
import sys
import uuid
import smbprotocol
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, FileAttributes, CreateDisposition
from impacket.dcerpc.v5 import transport, scmr

# Initialize colorama
init(autoreset=True)

# Create a Figlet object with a larger font
fig = Figlet(font='big')

# Render the text
ascii_art = fig.renderText('ADVISION')

# Print the ASCII art logo in a bold color
print(Fore.CYAN + Style.BRIGHT + ascii_art)

# Configure logging
def configure_logging(verbosity):
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stdout)
    if verbosity:
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt="%(levelname)s - %(message)s")
    else:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(fmt="%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def generate_report(naming_contexts_data, filter_option):
    # Initialize PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Add the signature text "Red Team Beta"
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(200, 10, txt="Red Team Beta", ln=True, align='C')
    pdf.ln(10)

    # Add a title for the report
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="LDAP Enumeration Report", ln=True, align='C')
    pdf.ln(10)

    # Add the filter option used
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt=f"Filter applied: {filter_option.upper()}", ln=True, align='L')
    pdf.ln(5)

    # Add naming context details in a structured format
    pdf.set_font("Arial", size=12)
    for context, entries in naming_contexts_data.items():
        pdf.ln(10)
        pdf.cell(200, 10, txt=f"Naming Context: {context}", ln=True, align='L')
        pdf.ln(5)
        pdf.cell(200, 10, txt="Entries:", ln=True, align='L')
        pdf.ln(5)

        # List all entries for each context
        for entry in entries:
            try:
                entry_str = str(entry).encode('latin-1', errors='ignore').decode('latin-1')
                pdf.multi_cell(200, 10, txt=entry_str, align='L')
                pdf.ln(2)  # Add space between entries
            except Exception as e:
                print(f"Error encoding entry: {e}")
        
        pdf.ln(5)  # Add more space between contexts

    # Save PDF
    pdf.output("ldapenumerationresults.pdf")
    print(Fore.GREEN + "Report successfully generated: ldapenumerationresults.pdf")
def test_smb_connection(server_ip, username, password, logger):
    try:
        logger.info(f"Attempting SMB connection to {server_ip}...")

        # Establish SMB connection
        connection = Connection(uuid.uuid4(), server_ip, 445)
        connection.connect()
        logger.info("Connected to SMB server.")

        # Create a session and authenticate
        session = Session(connection, username, password)
        session.connect()
        logger.info(f"SMB session established as {username}.")

        # Enumerate shares
        logger.info("Enumerating SMB shares...")
        tree = TreeConnect(session, r"\\{}\\IPC$".format(server_ip))
        tree.connect()

        share_list = session.enumerate_shares()
        for share in share_list:
            logger.info(f"Share found: {share['ShareName']}")

        # Attempt access to each share
        for share in share_list:
            try:
                logger.info(f"Trying access to {share['ShareName']}...")
                tree = TreeConnect(session, r"\\{}\\{}".format(server_ip, share['ShareName']))
                tree.connect()
                logger.info(f"Access to {share['ShareName']} successful.")
            except Exception as e:
                logger.error(f"Access to {share['ShareName']} failed: {e}")

    except Exception as e:
        logger.error(f"SMB connection failed: {e}")
    finally:
        try:
            connection.disconnect()
            logger.info("Disconnected from SMB server.")
        except:
            pass





def test_dcom_connection(server_ip, username, password, domain, logger):
    try:
        logger.info(f"Attempting DCOM connection to {server_ip}...")

        # Build the DCOM connection string
        dcom_conn_string = r'ncacn_ip_tcp:{}[135]'.format(server_ip)

        # Set up DCOM authentication
        auth_transport = transport.DCERPCTransportFactory(dcom_conn_string)
        auth_transport.set_credentials(username, password, domain)

        # Establish the DCOM connection
        dcom_connection = auth_transport.get_dce_rpc()
        dcom_connection.connect()
        logger.info("DCOM connection established.")

        # Bind to the Service Control Manager (SCM) to test DCOM execution
        dcom_connection.bind(scmr.MSRPC_UUID_SCMR)
        logger.info("Bound to SCMR (Service Control Manager).")

        # Retrieve services list as a basic test
        handle = scmr.hROpenSCManagerW(dcom_connection)
        services = scmr.hREnumServicesStatusW(dcom_connection, handle['lpScHandle'])
        logger.info("Services retrieved from the SCM via DCOM:")

        for service in services:
            logger.info(f"Service Name: {service['lpServiceName']} - Display Name: {service['lpDisplayName']}")

    except Exception as e:
        logger.error(f"DCOM connection failed: {e}")
    finally:
        try:
            dcom_connection.disconnect()
            logger.info("Disconnected from DCOM server.")
        except:
            pass


def enumerate_naming_contexts(connection, logger, filter_option):
    naming_contexts = connection.server.info.naming_contexts
    naming_contexts_data = {}

    for context in naming_contexts:
        logger.info(f"Found naming context: {context}")
        logger.info(f"Performing search in naming context: {context}")
        
        # Apply a search filter based on the filter_option provided
        if filter_option == "users":
            search_filter = '(objectClass=user)'
        else:
            search_filter = '(objectClass=*)'  # Default: fetch all objects
        
        connection.search(search_base=context, search_filter=search_filter, search_scope=ldap3.SUBTREE, attributes=ldap3.ALL_ATTRIBUTES)
        
        # Save entries for report
        entries = connection.entries
        naming_contexts_data[context] = entries

        # Output the found entries
        for entry in entries:
            logger.info(f"Found entry: {entry}")

    # Generate a PDF report
    generate_report(naming_contexts_data, filter_option)

def retrieve_password_policy(server_ip, username, password):
    # Create a session
    session = winrm.Session(
        server_ip,
        auth=(username, password),
        transport='ntlm'
    )

    # PowerShell command to retrieve password policy
    ps_script = """
    Get-ADDefaultDomainPasswordPolicy | Select-Object -Property MaxPasswordAge, MinPasswordLength, PasswordHistorySize, LockoutThreshold, LockoutDuration, LockoutObservationWindow
    """

    # Execute the command
    result = session.run_ps(ps_script)

    # Print the result
    print(result.std_out.decode())
    if result.std_err:
        print("Errors:")
        print(result.std_err.decode())

def retrieve_sid_history(server_ip, username, password, target_user):
    # Create a session using WinRM to execute the PowerShell command
    session = winrm.Session(
        server_ip,
        auth=(username, password),
        transport='ntlm'
    )

    # PowerShell script to retrieve SID history for a target user
    ps_script = f"""
    Get-ADUser -Identity {target_user} -Properties SIDHistory | Select-Object -Property Name, SIDHistory
    """

    # Execute the command
    result = session.run_ps(ps_script)

    # Check if any error occurred
    if result.std_err:
        print(f"Errors: {result.std_err.decode()}")
    else:
        print(result.std_out.decode())

def retrieve_schema_info(connection, logger):
    try:
        logger.info("Retrieving LDAP schema information...")

        # Using the configurationNamingContext to locate schema location
        base_dn = 'CN=Schema,' + connection.server.info.other['configurationNamingContext'][0]
        logger.info(f"Using search base: {base_dn}")

        # Search for all objects in the schema with objectClass 'subSchema'
        connection.search(
            search_base=base_dn,
            search_filter='(objectClass=subSchema)',
            search_scope=ldap3.SUBTREE,
            attributes=ldap3.ALL_ATTRIBUTES
        )

        if connection.entries:
            logger.info("LDAP Schema Information Retrieved:")
            for entry in connection.entries:
                print(entry)
        else:
            logger.error("No schema information found.")
    except Exception as e:
        logger.error(f"Failed to retrieve LDAP schema information. Error: {e}")

def retrieve_ad_hierarchy(connection, logger):
    base_dn = connection.server.info.other['defaultNamingContext'][0]
    logger.info(f"Using base DN: {base_dn}")

    # Search for all objects in the domain
    search_filter = "(objectClass=*)"
    connection.search(search_base=base_dn, search_filter=search_filter, search_scope=ldap3.SUBTREE, attributes=['distinguishedName', 'objectClass'])

    if connection.entries:
        logger.info("Active Directory Hierarchy Retrieved:")
        # Store the hierarchy as a dictionary where the key is the parent DN and values are the children
        ad_hierarchy = defaultdict(list)
        for entry in connection.entries:
            dn = entry['distinguishedName'].value
            parent_dn = get_parent_dn(dn)
            ad_hierarchy[parent_dn].append(dn)

        # Display the hierarchy starting from the base DN
        display_hierarchy(ad_hierarchy, base_dn, logger)
    else:
        logger.error("No AD objects found.")

# Helper function to get the parent DN of a given distinguishedName
def get_parent_dn(dn):
    parts = dn.split(',')
    return ','.join(parts[1:]) if len(parts) > 1 else ''

# Recursive function to display hierarchy
def display_hierarchy(hierarchy, current_dn, logger, level=0):
    indent = ' ' * (level * 4)
    logger.info(f"{indent}- {current_dn}")
    if current_dn in hierarchy:
        for child_dn in hierarchy[current_dn]:
            display_hierarchy(hierarchy, child_dn, logger, level + 1)

# New GPO enumeration functionality
def enumerate_gpos(connection, logger):
    logger.info("Retrieving Group Policy Objects (GPOs)...")

    # Search for all Group Policy Objects (GPOs) in the domain
    gpo_base_dn = 'CN=Policies,CN=System,' + connection.server.info.other['defaultNamingContext'][0]
    logger.info(f"Searching for GPOs in {gpo_base_dn}")

    # Perform LDAP search for GPOs
    connection.search(
        search_base=gpo_base_dn,
        search_filter='(objectClass=groupPolicyContainer)',
        search_scope=ldap3.SUBTREE,
        attributes=['cn', 'displayName', 'gPCFileSysPath', 'gPCMachineExtensionNames', 'nTSecurityDescriptor']
    )

    # If GPOs are found, display the information
    if connection.entries:
        logger.info("Group Policy Objects found:")
        for gpo in connection.entries:
            display_gpo_info(gpo, logger)
    else:
        logger.error("No Group Policy Objects (GPOs) found in the domain.")

# Display detailed information for each GPO
def display_gpo_info(gpo, logger):
    logger.info(f"GPO Name: {gpo['displayName'].value}")
    logger.info(f"GPO CN: {gpo['cn'].value}")
    logger.info(f"GPO File Path: {gpo['gPCFileSysPath'].value}")
    logger.info(f"GPO Extensions: {gpo['gPCMachineExtensionNames'].value}")
    
    # Permissions - this can require parsing nTSecurityDescriptor
    logger.info(f"GPO Permissions (raw nTSecurityDescriptor): {gpo['nTSecurityDescriptor'].value}")

# New DNS misconfiguration check functionality
class DNSMisconfigurationChecker:
    def __init__(self, domain, dc_ip):
        self.domain = domain
        self.dc_ip = dc_ip

        # Custom DNS resolver to directly use the DC IP
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [self.dc_ip]
        self.resolver.timeout = 3  # Set timeout for each query to 3 seconds
        self.resolver.lifetime = 5  # Total query lifetime limit

    def run_checks(self):
        print(f"[*] Running DNS misconfiguration checks for domain: {self.domain} with DC IP: {self.dc_ip}")
        self.check_zone_transfer()
        self.check_open_resolver()
        self.check_reverse_lookup()
        self.check_dnssec()
        self.check_dynamic_dns()
        self.enumerate_records()

    def check_zone_transfer(self):
        print("[*] Checking for Zone Transfer Vulnerability...")
        try:
            ns = self.resolver.resolve(self.domain, 'NS')
            for server in ns:
                ip = str(self.resolver.resolve(server.target, 'A')[0])
                print(f"[*] Trying Zone Transfer on {server.target} ({ip})")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ip, self.domain))
                    if zone:
                        print(f"[+] Zone Transfer successful on {server.target} ({ip})")
                        for name, node in zone.nodes.items():
                            print(f"[Zone Entry] {name.to_text()} - {node.to_text(zone[name])}")
                        self.exploit_zone_transfer()
                        return
                except Exception as e:
                    print(f"[-] Zone Transfer failed on {server.target} ({ip}): {e}")
        except dns.resolver.NoAnswer:
            print("[-] No NS records found, skipping zone transfer check.")
        except dns.resolver.NXDOMAIN:
            print(f"[-] Error: Domain {self.domain} does not exist. Verify the domain name.")
        except dns.resolver.Timeout:
            print(f"[-] Zone Transfer check timed out.")
        except Exception as e:
            print(f"Error in DNS resolution: {e}")

    def check_open_resolver(self):
        print("[*] Checking for Open Resolver Vulnerability...")
        try:
            answer = self.resolver.resolve('google.com', 'A')  # Query for 'google.com' as a test
            print(f"[+] Open resolver found! Resolved IP: {answer[0]}")
            self.exploit_open_resolver()
        except Exception as e:
            print(f"[-] Open resolver check failed: {e}")

    def check_reverse_lookup(self):
        print("[*] Checking for Missing Reverse Lookup Zones...")
        try:
            reverse_zone = '.'.join(reversed(self.dc_ip.split('.'))) + ".in-addr.arpa"
            answer = self.resolver.resolve(reverse_zone, 'PTR')
            print(f"[+] Reverse lookup zone exists: {answer}")
        except dns.resolver.NXDOMAIN:
            print(f"[-] Reverse lookup zone does not exist for IP: {self.dc_ip}. This might indicate a misconfiguration.")
            self.exploit_missing_reverse()
        except dns.resolver.Timeout:
            print(f"[-] Reverse lookup zone check timed out.")
        except Exception as e:
            print(f"[-] Error checking reverse lookup zone: {e}")

    def check_dnssec(self):
        print("[*] Checking if DNSSEC is properly configured...")
        try:
            query = dns.message.make_query(self.domain, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.udp(query, self.resolver.nameservers[0])

            if response.flags & dns.flags.AD:
                print("[+] DNSSEC is properly configured.")
            else:
                print("[-] DNSSEC is not configured or not functioning properly.")
                self.exploit_dnssec()
        except dns.resolver.NoAnswer:
            print("[-] DNSSEC is not enabled or no DNSKEY records found.")
        except dns.resolver.Timeout:
            print("[-] DNSSEC check timed out.")
        except Exception as e:
            print(f"[-] Error checking DNSSEC: {e}")

    def check_dynamic_dns(self):
        print("[*] Checking if Dynamic DNS is enabled...")
        try:
            srv_records = ["_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_msdcs"]
            for srv in srv_records:
                fqdn = f"{srv}.{self.domain}"
                answer = self.resolver.resolve(fqdn, 'SRV')
                if answer:
                    print(f"[+] Dynamic DNS is enabled for {fqdn}")
                    for rdata in answer:
                        print(f"[SRV Record] {rdata}")
                    self.exploit_dynamic_dns()
        except dns.resolver.NXDOMAIN:
            print(f"[-] SRV records not found, Dynamic DNS may not be enabled.")
        except dns.resolver.Timeout:
            print(f"[-] Dynamic DNS check timed out.")
        except Exception as e:
            print(f"[-] Dynamic DNS check failed: {e}")

    def enumerate_records(self):
        print("[*] Enumerating common DNS records (A, MX, TXT, CNAME, SRV)...")
        record_types = ['A', 'MX', 'TXT', 'CNAME', 'SRV']
        for record_type in record_types:
            try:
                answer = self.resolver.resolve(self.domain, record_type)
                print(f"[+] Found {record_type} records for {self.domain}:")
                for rdata in answer:
                    print(f"  {rdata}")
            except dns.resolver.NoAnswer:
                print(f"[-] No {record_type} records found for {self.domain}.")
            except dns.resolver.NXDOMAIN:
                print(f"[-] Domain {self.domain} does not exist. Skipping {record_type} lookup.")
                break
            except dns.resolver.Timeout:
                print(f"[-] {record_type} lookup for {self.domain} timed out.")
            except Exception as e:
                print(f"[-] Error during {record_type} lookup: {e}")

    # Exploitation functions
    def exploit_zone_transfer(self):
        print("[!] Exploitation tip: Use retrieved zone data to enumerate internal resources.")
    
    def exploit_open_resolver(self):
        print("[!] Exploitation tip: Attackers can abuse open resolvers for DNS amplification attacks.")

    def exploit_missing_reverse(self):
        print("[!] Exploitation tip: Missing reverse lookups can cause issues with IP tracking and identification.")
    
    def exploit_dnssec(self):
        print("[!] Exploitation tip: If DNSSEC is not configured, attackers can perform DNS spoofing and cache poisoning attacks.")
    
    def exploit_dynamic_dns(self):
        print("[!] Exploitation tip: If Dynamic DNS is enabled without proper authentication, attackers can potentially update DNS records and redirect traffic.")

def signal_handler(sig, frame):
    print("\n[!] Exiting the script. Ctrl+C detected.")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)  # Allow script to be interrupted by Ctrl+C
    
    arg_parser = argparse.ArgumentParser(description="LDAP Server Info Retriever with NTLM Authentication and Enumeration")
    arg_parser.add_argument(
        "-ip", "--server", dest="ldap_server", required=True, help="IP address of the LDAP server."
    )
    arg_parser.add_argument(
        "-p", "--port", dest="port", type=int, default=389, help="Port number (default is 389)."
    )
    arg_parser.add_argument(
        "-d", "--domain", dest="domain", required=True, help="Domain for NTLM authentication."
    )
    arg_parser.add_argument(
        "-u", "--username", dest="username", required=True, help="Username for NTLM authentication."
    )
    arg_parser.add_argument(
        "-P", "--password", dest="password", required=True, help="Password for NTLM authentication."
    )
    arg_parser.add_argument(
        "-pwp", "--passwordpolicy", action="store_true", help="Retrieve domain password policy."
    )
    arg_parser.add_argument(
        "-H", "--hierarchy", action="store_true", help="Retrieve Active Directory hierarchy."
    )
    arg_parser.add_argument(
        "--schema", action="store_true", help="Retrieve schema information."
    )
    arg_parser.add_argument(
        "-f", "--filter", dest="filter", type=str, default="all", choices=["all", "users"], help="Filter option: all, users (default: all)."
    )
    arg_parser.add_argument(
        "-v", "--verbose", dest="verbosity", help="Turn on debug mode", action="store_true"
    )
    arg_parser.add_argument(
        "-gpo", "--gpo", help="Flag to enumerate GPOs", action="store_true"
    )
    arg_parser.add_argument(
        "-dns", "--dns", dest="check_dns", action="store_true", help="Check DNS misconfigurations."
    )
    arg_parser.add_argument(
        "--sidhistory", help="Retrieve SID history for a user", action="store_true"
    )
    arg_parser.add_argument("--smb", help="Test SMB connectivity and share enumeration", action="store_true")
    arg_parser.add_argument("--dcom", help="Test DCOM connectivity", action="store_true")
    args = arg_parser.parse_args()

    # Configure logging
    logger = configure_logging(args.verbosity)

    # Create user_dn for NTLM authentication
    user_dn = f"{args.domain}\\{args.username}"

    try:
        # Connect to the LDAP server
        server = ldap3.Server(args.ldap_server, port=args.port, get_info=ldap3.ALL)
        logger.info(f"Attempting to connect to {args.ldap_server} on port {args.port}...")

        # Using NTLM Authentication
        connection = ldap3.Connection(server, user=user_dn, password=args.password, authentication=ldap3.NTLM)

        # Attempt to bind
        if connection.bind():
            logger.info(f"Successfully connected and bound to the LDAP server as {user_dn}.")

            # Check if specific flags are used
            if args.passwordpolicy:
                retrieve_password_policy(args.ldap_server, args.username, args.password)
            elif args.hierarchy:
                retrieve_ad_hierarchy(connection, logger)
            elif args.schema:
                retrieve_schema_info(connection, logger)
            elif args.gpo:
                enumerate_gpos(connection, logger)
            elif args.check_dns:
                domain = input("Enter the domain for DNS checks: ")
                dc_ip = input("Enter the domain controller IP: ")
                checker = DNSMisconfigurationChecker(domain, dc_ip)
                checker.run_checks()
            elif args.sidhistory:
                target_user = input("Enter the username to check SID history: ")
                retrieve_sid_history(args.ldap_server, args.username, args.password, target_user)
            elif args.smb:
                test_smb_connection(args.ldap_server, args.username, args.password, logger)
            elif args.dcom:
                test_dcom_connection(args.ldap_server, args.username, args.password, args.domain, logger)
            else:
                # Perform LDAP enumeration
                enumerate_naming_contexts(connection, logger, args.filter)

        else:
            logger.error("Failed to bind to the LDAP server. Check your credentials and try again.")

    except ldap3.LDAPException as e:
        logger.error(f"LDAP Error: {e}")
    except Exception as e:
        logger.error(f"Unexpected Error: {e}")

if __name__ == "__main__":
    main()
