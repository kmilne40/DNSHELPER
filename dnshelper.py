import re
import logging
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import whois
from tabulate import tabulate
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

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
    Validate the given domain name using a basic regex.
    
    Parameters:
        domain (str): The domain name to validate.
    
    Returns:
        bool: True if domain matches a reasonable pattern, False otherwise.
    """
    # Basic regex for domain validation: checks general domain formats.
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\."
        r"(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)*[A-Za-z]{2,63}$"
    )
    return bool(domain_regex.match(domain))

def is_valid_ip(ip_address):
    """
    Validate the given IP address using the ipaddress module.
    
    Parameters:
        ip_address (str): The IP address to validate.
    
    Returns:
        bool: True if a valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def dns_lookup(domain):
    """
    Perform an A record DNS lookup for the specified domain.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'A')
        data = [(rdata.address,) for rdata in answers]
        print_table(data, ["IP Address"])
    except dns.resolver.NoAnswer:
        print(f"No A records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during A record lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during A record lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def mx_lookup(domain):
    """
    Perform an MX record DNS lookup for the specified domain.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        data = [(rdata.exchange.to_text(),) for rdata in answers]
        print_table(data, ["Mail Server"])
    except dns.resolver.NoAnswer:
        print(f"No MX records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during MX lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during MX lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def ns_lookup(domain):
    """
    Perform an NS record DNS lookup for the specified domain.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        data = [(rdata.target.to_text(),) for rdata in answers]
        print_table(data, ["Name Server"])
    except dns.resolver.NoAnswer:
        print(f"No NS records found for {domain}.")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist.")
    except dns.exception.DNSException as e:
        logging.error(f"DNS error during NS lookup for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        logging.error(f"Unexpected error during NS lookup for {domain}: {e}")
        print("An unexpected error occurred.")

def soa_lookup(domain):
    """
    Perform an SOA record DNS lookup for the specified domain.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        answers = dns.resolver.resolve(domain, 'SOA')
        data = [
            (rdata.mname.to_text(), rdata.rname.to_text(), rdata.serial,
             rdata.refresh, rdata.retry, rdata.expire, rdata.minimum)
            for rdata in answers
        ]
        headers = ["Primary Name Server", "Responsible Person", "Serial Number",
                   "Refresh Interval", "Retry Interval", "Expire Limit", "Minimum TTL"]
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
    
    Parameters:
        ip_address (str): The IP address to query.
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

def whois_lookup(domain):
    """
    Perform a WHOIS lookup for the specified domain.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        w = whois.whois(domain)
        # Safely extract fields; whois data can be missing keys.
        data = [
            ("Domain Name", w.get('domain_name')),
            ("Registrar", w.get('registrar')),
            ("Creation Date", w.get('creation_date')),
            ("Expiration Date", w.get('expiration_date')),
            ("Name Servers", w.get('name_servers'))
        ]
        # Filter out None values for cleaner output
        data = [(key, value) for key, value in data if value is not None]
        print_table(data, ["Field", "Value"])
    except Exception as e:
        # The whois module often raises various exceptions if data is not found or parse fails
        logging.error(f"WHOIS lookup error for {domain}: {e}")
        print("WHOIS lookup error occurred.")

def get_all_information(domain):
    """
    Retrieve and display comprehensive DNS and WHOIS information about the domain.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return

    print(f"Getting all information for domain: {domain}")
    print("-" * 30)

    # DNS A Lookup
    print("DNS Lookup:")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [rdata.address for rdata in answers]
        print_table([(ip,) for ip in ip_addresses], ["IP Address"])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        ip_addresses = []
        print(f"No A records found for {domain}.")
    except dns.exception.DNSException as e:
        ip_addresses = []
        logging.error(f"DNS error during get_all_information (A records) for {domain}: {e}")
        print("DNS error occurred.")
    except Exception as e:
        ip_addresses = []
        logging.error(f"Unexpected error during get_all_information (A records) for {domain}: {e}")
        print("An unexpected error occurred.")

    print("\nMX Lookup:")
    mx_lookup(domain)

    print("\nNS Lookup:")
    ns_lookup(domain)

    print("\nSOA Lookup:")
    soa_lookup(domain)

    # Reverse DNS Lookup (if we have at least one IP)
    if ip_addresses:
        print("\nReverse DNS Lookup (first IP):")
        reverse_lookup(ip_addresses[0])
    else:
        print("\nNo IP addresses available for reverse lookup.")

    print("\nWHOIS Lookup:")
    whois_lookup(domain)

def zone_transfer(domain):
    """
    Attempt a DNS zone transfer from the domain's name servers.
    
    Parameters:
        domain (str): The domain name to query.
    """
    if not is_valid_domain(domain):
        print(f"Invalid domain format: {domain}")
        return
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        # Try each name server for a zone transfer until one succeeds or all fail
        for ns_record in ns_records:
            ns_server = str(ns_record.target)
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

def main_menu():
    """
    Display the main menu ASCII art and options.
    """
    ascii_art = """
      \033[91mDDD\033[0m\033[91m   N   N  SSS
     \033[91m D  D  NN  N S
     \033[91m D  D  N N N  SSS
     \033[91m D  D  N  NN     S
      \033[91mDDD\033[0m\033[91m   N   N  SSS
    """
    print(ascii_art)
    print("\033[91m      Kev's DNS Helper\033[0m\n")
    print("Domain Reconnaissance and DNS Queries\n")
    print("1. Perform DNS Lookup")
    print("2. Perform MX Lookup")
    print("3. Perform NS Lookup")
    print("4. Perform SOA Lookup")
    print("5. Perform Reverse DNS Lookup")
    print("6. Perform WHOIS Lookup")
    print("7. Get All Information")
    print("8. Perform Zone Transfer")
    print("\033[91m9. Exit\033[0m")

def main():
    """
    Main function to run the interactive menu and handle user input.
    """
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
        else:
            print("Invalid choice. Please enter a number from 1 to 9.")

if __name__ == "__main__":
    main()
