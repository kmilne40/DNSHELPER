#!/usr/bin/env python3

import re
import logging
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import whois
from tabulate import tabulate
import ipaddress
import subprocess

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)


# =============================================================================
# Utility Functions
# =============================================================================
def print_table(data, headers):
    """
    Print a table using the provided data and headers.
    
    Parameters:
        data (list of tuples): Data rows to print.
        headers (list of str): Column headers.
    """
    if data:
        print(tabulate(data, headers=headers, tablefmt="pretty"))
    else:
        print("No data available.")


def is_valid_domain(domain):
    """
    Validate the given domain (including possible subdomains).
    
    By default, this pattern allows multi-level subdomains.
    You may wish to refine or remove this check if needed for brute-forcing.
    """
    domain_regex = re.compile(
        r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    )
    return bool(domain_regex.match(domain))


def is_valid_ip(ip_address):
    """
    Validate the given IP address using the ipaddress module.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


# =============================================================================
# DNS Lookup Functions
# =============================================================================
def generic_dns_lookup(domain, record_type):
    """
    Perform a DNS lookup of the specified record_type for the domain.
    Returns a list of resolved data strings or an empty list if none.
    
    Parameters:
        domain (str): Domain name to query.
        record_type (str): The DNS record type, e.g., "A", "MX", "NS", "SOA", etc.
    """
    if not is_valid_domain(domain):
        logging.warning(f"Domain might be invalid according to the regex: {domain}")
        return []

    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata.to_text()) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.DNSException as e:
        logging.error(f"DNS error ({record_type}) for {domain}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error ({record_type}) for {domain}: {e}")
        return []


def dns_lookup(domain):
    """
    Perform an A record DNS lookup for the specified domain.
    """
    results = generic_dns_lookup(domain, 'A')
    if results:
        data = [(r,) for r in results]
        print_table(data, ["IP Address"])
    else:
        print(f"No A records found for {domain} or domain is invalid.")


def mx_lookup(domain):
    """
    Perform an MX record DNS lookup for the specified domain.
    """
    results = generic_dns_lookup(domain, 'MX')
    parsed = []
    for mx_rec in results:
        # Typically "10 mail.example.com."
        parts = mx_rec.split()
        if len(parts) == 2:
            parsed.append((parts[1].rstrip("."),))  # keep only the mail server
        else:
            parsed.append((mx_rec,))

    if parsed:
        print_table(parsed, ["Mail Server"])
    else:
        print(f"No MX records found for {domain}")


def ns_lookup(domain):
    """
    Perform an NS record DNS lookup for the specified domain.
    """
    results = generic_dns_lookup(domain, 'NS')
    if results:
        data = [(r.rstrip("."),) for r in results]
        print_table(data, ["Name Server"])
    else:
        print(f"No NS records found for {domain}")


def soa_lookup(domain):
    """
    Perform an SOA record DNS lookup for the specified domain.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        data = []
        for rdata in answers:
            data.append((
                rdata.mname.to_text(),
                rdata.rname.to_text(),
                rdata.serial,
                rdata.refresh,
                rdata.retry,
                rdata.expire,
                rdata.minimum
            ))
        headers = [
            "Primary Name Server", "Responsible Person", "Serial Number",
            "Refresh Interval", "Retry Interval", "Expire Limit", "Minimum TTL"
        ]
        print_table(data, headers)
    except dns.resolver.NoAnswer:
        print(f"No SOA records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during SOA lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during SOA lookup for {domain}: {e}")
        print("An unexpected error occurred.")


def reverse_lookup(ip_address):
    """
    Perform a reverse DNS lookup on the specified IP address.
    """
    if not is_valid_ip(ip_address):
        print(f"Invalid IP address: {ip_address}")
        return

    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        data = [(rdata.target.to_text(),) for rdata in answers]
        print_table(data, ["Domain Name"])
    except dns.resolver.NoAnswer:
        print(f"No PTR records found for {ip_address}.")
    except dns.resolver.NXDOMAIN:
        print(f"No reverse DNS record exists for {ip_address}.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during reverse lookup for {ip_address}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during reverse lookup for {ip_address}: {e}")
        print("An unexpected error occurred.")


# =============================================================================
# WHOIS Lookup
# =============================================================================
def whois_lookup(domain):
    """
    Perform a WHOIS lookup for the specified domain.
    Displays all keys parsed by the python-whois library.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    try:
        w = whois.whois(domain)
        data = []
        for key, value in w.items():
            if value:
                # Convert lists to comma-separated strings for readability
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value)
                data.append((key, str(value)))

        if data:
            print_table(data, ["Field", "Value"])
        else:
            print("No WHOIS information found (the whois library returned empty fields).")

        # ---------------------------------------------------------------------
        # Optional: Raw WHOIS fallback (uncomment if you want to see raw output)
        #
        # try:
        #     raw_output = subprocess.check_output(["whois", domain], text=True)
        #     print("\nRaw WHOIS Output:\n")
        #     print(raw_output)
        # except Exception as e:
        #     logging.error(f"Error retrieving raw WHOIS data: {e}")
        # ---------------------------------------------------------------------

    except Exception as e:
        logging.error(f"WHOIS lookup error for {domain}: {e}")
        print("WHOIS lookup error occurred.")


# =============================================================================
# Get All Information
# =============================================================================
def get_all_information(domain):
    """
    Retrieve and display comprehensive DNS and WHOIS information about the domain.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    print(f"Getting all information for domain: {domain}")
    print("-" * 30)

    # DNS A Lookup
    print("DNS Lookup (A record):")
    ip_addresses = generic_dns_lookup(domain, 'A')
    if ip_addresses:
        print_table([(ip,) for ip in ip_addresses], ["IP Address"])
    else:
        print(f"No A records found for {domain}.")

    # MX Lookup
    print("\nMX Lookup:")
    mx_lookup(domain)

    # NS Lookup
    print("\nNS Lookup:")
    ns_lookup(domain)

    # SOA Lookup
    print("\nSOA Lookup:")
    soa_lookup(domain)

    # Reverse DNS Lookup (first IP if exists)
    if ip_addresses:
        print("\nReverse DNS Lookup (for first IP):")
        reverse_lookup(ip_addresses[0])
    else:
        print("\nNo IP addresses available for reverse lookup.")

    # WHOIS Lookup
    print("\nWHOIS Lookup:")
    whois_lookup(domain)


# =============================================================================
# Zone Transfer
# =============================================================================
def zone_transfer(domain):
    """
    Attempt a DNS zone transfer from the domain's name servers.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        # Try each name server for a zone transfer
        for ns_record in ns_records:
            ns_server = str(ns_record.target).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=5))
                if zone:
                    print(f"Zone transfer results for domain: {domain}")
                    print(zone.to_text())
                    return
            except dns.exception.DNSException as e:
                logging.info(f"Zone transfer failed at {ns_server} for {domain}: {e}")
        print("Zone transfer did not succeed with any name server.")
    except dns.resolver.NoAnswer:
        print(f"No NS records found for {domain}, cannot attempt zone transfer.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during zone transfer for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during zone transfer for {domain}: {e}")
        print("An unexpected error occurred.")


# =============================================================================
# Subdomain Brute Force
# =============================================================================
def subdomain_brute_force(domain, wordlist_path):
    """
    Brute force subdomains for a given domain using a wordlist file.
    
    Parameters:
        domain (str): The base domain, e.g., "example.com"
        wordlist_path (str): Path to the text file containing subdomains, one per line.
    """
    # For subdomain brute force, you may remove domain validation if you want
    # to brute force wildcard or unusual domain patterns.
    if not is_valid_domain(domain):
        print(f"Warning: {domain} might not pass regex validation.")
        print("You may need to loosen the regex or skip validation for subdomain brute forcing.\n")

    print(f"[*] Starting subdomain brute force for: {domain}")
    print(f"[*] Using subdomain wordlist: {wordlist_path}\n")

    try:
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Wordlist file not found: {wordlist_path}")
        return
    except Exception as e:
        logging.error(f"Error reading subdomain file '{wordlist_path}': {e}")
        return

    found_subdomains = []
    for sub in subdomains:
        brute_domain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(brute_domain, 'A')
            ip_addresses = [rdata.address for rdata in answers]
            found_subdomains.append((brute_domain, ", ".join(ip_addresses)))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.DNSException as e:
            logging.debug(f"DNS error for subdomain {brute_domain}: {e}")
            pass

    if found_subdomains:
        print("Discovered subdomains:\n")
        print_table(found_subdomains, ["Subdomain", "Resolved IP(s)"])
    else:
        print("No subdomains were discovered.")


# =============================================================================
# Menu and Main
# =============================================================================
def main_menu():
    """
    Display the main menu ASCII art and options.
    """
    ascii_art = r"""
      DDD   N   N  SSS
     D  D   NN  N S
     D  D   N N N  SSS
     D  D   N  NN     S
      DDD   N   N  SSS
    """
    print(ascii_art)
    print("Kev's DNS Helper\n")
    print("Domain Reconnaissance and DNS Queries\n")
    print("1. Perform DNS Lookup (A)")
    print("2. Perform MX Lookup")
    print("3. Perform NS Lookup")
    print("4. Perform SOA Lookup")
    print("5. Perform Reverse DNS Lookup")
    print("6. Perform WHOIS Lookup")
    print("7. Get All Information (DNS + WHOIS)")
    print("8. Perform Zone Transfer")
    print("9. Exit")
    print("10. Brute Force Subdomains\n")


def main():
    while True:
        main_menu()
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            domain = input("Enter domain name: ").strip()
            dns_lookup(domain)

        elif choice == '2':
            domain = input("Enter domain name: ").strip()
            mx_lookup(domain)

        elif choice == '3':
            domain = input("Enter domain name: ").strip()
            ns_lookup(domain)

        elif choice == '4':
            domain = input("Enter domain name: ").strip()
            soa_lookup(domain)

        elif choice == '5':
            ip_address = input("Enter IP Address: ").strip()
            reverse_lookup(ip_address)

        elif choice == '6':
            domain = input("Enter domain name: ").strip()
            whois_lookup(domain)

        elif choice == '7':
            domain = input("Enter domain name: ").strip()
            get_all_information(domain)

        elif choice == '8':
            domain = input("Enter domain name: ").strip()
            zone_transfer(domain)

        elif choice == '9':
            print("Exiting...")
            break

        elif choice == '10':
            domain = input("Enter domain name: ").strip()
            subdomains_file = input("Enter path to subdomain wordlist: ").strip()
            subdomain_brute_force(domain, subdomains_file)

        else:
            print("Invalid choice. Please enter a number from 1 to 10.")


if __name__ == "__main__":
    main()
