import argparse
import requests
import time
import logging
import subprocess
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Optional
from colorama import Fore, Style, init

init(autoreset=True)

# Setup logging: file + console
logger = logging.getLogger('domain_checker')
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('domain_checker.log')
file_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


def resolve_domain(domain: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(domain)
        logger.debug(f"Resolved {domain} to {ip}")
        return ip
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {domain}: {e}")
        return None


def ping_host(host: str, timeout: int = 2, count: int = 1) -> bool:
    """
    Ping host cross-platform.
    Windows: -n count, timeout in ms is not supported via -W so ignored.
    Linux/macOS: -c count, -W timeout in seconds.
    """
    try:
        param_count = '-n' if sys.platform.startswith('win') else '-c'
        cmd = ['ping', param_count, str(count)]
        # Timeout param: only works on Unix-like systems, Windows ignores -W
        if not sys.platform.startswith('win'):
            cmd += ['-W', str(timeout)]
        cmd.append(host)

        result = subprocess.run(cmd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=timeout + 2)
        success = result.returncode == 0
        logger.debug(f"Ping {host} returncode={result.returncode} success={success}")
        return success
    except subprocess.TimeoutExpired:
        logger.debug(f"Ping timeout expired for {host}")
        return False
    except Exception as e:
        logger.debug(f"Ping error on {host}: {e}")
        return False


def check_port(host: str, port: int, timeout: int = 2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            logger.debug(f"Port {port} open on {host}")
            return True
    except Exception:
        logger.debug(f"Port {port} closed on {host}")
        return False


def check_http(domain: str, timeout: int = 5, retries: int = 2) -> Tuple[bool, Optional[int], Optional[float], Optional[str]]:
    protocols = ['https://', 'http://']
    for proto in protocols:
        for attempt in range(1, retries + 1):
            try:
                start = time.time()
                response = requests.get(f'{proto}{domain}', timeout=timeout)
                elapsed = time.time() - start
                if response.status_code == 200:
                    logger.debug(f"{proto}{domain} returned 200 OK in {elapsed:.2f}s")
                    return True, response.status_code, elapsed, proto
                else:
                    logger.debug(f"{proto}{domain} returned status {response.status_code}")
                    return False, response.status_code, elapsed, proto
            except requests.RequestException as e:
                logger.debug(f"HTTP attempt {attempt} error for {proto}{domain}: {e}")
                time.sleep(0.5 * attempt)
    return False, None, None, None


def print_status(domain: str, http: Tuple[bool, Optional[int], Optional[float], Optional[str]], ping: bool,
                 ports_status: Dict[int, bool]) -> None:
    if http[0]:
        print(f"{Fore.GREEN}[+] {domain} is UP via {http[3]} (status: {http[1]}, response time: {http[2]:.2f}s){Style.RESET_ALL}")
        logger.info(f"{domain} is UP via {http[3]} (status: {http[1]}, response time: {http[2]:.2f}s)")
    else:
        status_info = http[1] if http[1] is not None else 'No response'
        print(f"{Fore.RED}[-] {domain} HTTP check failed (error/status: {status_info}){Style.RESET_ALL}")
        logger.warning(f"{domain} HTTP check failed (error/status: {status_info})")

    print(f"    Ping: {Fore.GREEN}Success{Style.RESET_ALL}" if ping else f"    Ping: {Fore.RED}Fail{Style.RESET_ALL}")

    for port, status in ports_status.items():
        color = Fore.GREEN if status else Fore.RED
        print(f"    Port {port}: {color}{'Open' if status else 'Closed'}{Style.RESET_ALL}")
    print()


def domain_check_worker(domain: str, ports: List[int], timeout_http: int, timeout_ping: int) -> Dict:
    """
    Esegue il controllo completo per un singolo dominio:
    - Risoluzione DNS
    - Ping
    - HTTP
    - Scan porte
    """
    result = {
        'domain': domain,
        'resolved_ip': None,
        'ping': False,
        'http': (False, None, None, None),
        'ports': {},
        'error': None
    }

    ip = resolve_domain(domain)
    if not ip:
        result['error'] = 'DNS resolution failed'
        return result
    result['resolved_ip'] = ip

    result['ping'] = ping_host(ip, timeout=timeout_ping)

    result['http'] = check_http(domain, timeout=timeout_http)

    ports_status = {}
    for port in ports:
        ports_status[port] = check_port(ip, port, timeout=timeout_http)
    result['ports'] = ports_status

    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description='Domain checker: ping, HTTP, port scan.'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domains', nargs='+', help='Domains to check')
    group.add_argument('-f', '--file', type=str, help='File with domains, one per line')

    parser.add_argument('-p', '--ports', nargs='*', type=int, default=[80, 443],
                        help='Ports to check (default: 80 443)')
    parser.add_argument('--timeout', type=int, default=5, help='HTTP and port scan timeout seconds (default: 5)')
    parser.add_argument('--ping-timeout', type=int, default=2, help='Ping timeout seconds (default: 2)')
    parser.add_argument('--workers', type=int, default=10, help='Number of parallel workers (default: 10)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    return parser.parse_args()


def main():
    args = parse_args()

    # Aggiorna livello logging console se verbose
    if args.verbose:
        console_handler.setLevel(logging.INFO)

    # Carica domini da file o argomenti
    if args.file:
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading file {args.file}: {e}")
            print(f"Error reading file {args.file}: {e}")
            sys.exit(1)
    else:
        domains = args.domains

    if not domains:
        print("No domains specified.")
        sys.exit(1)

    summary = {
        'up': [],
        'down': [],
        'http_response_times': [],
        'dns_fail': [],
    }

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_domain = {
            executor.submit(domain_check_worker, domain, args.ports, args.timeout, args.ping_timeout): domain
            for domain in domains
        }

        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
            except Exception as exc:
                logger.error(f"{domain} generated an exception: {exc}")
                print(f"{Fore.RED}Error checking {domain}: {exc}{Style.RESET_ALL}")
                continue

            if result['error']:
                print(f"{Fore.RED}[-] {domain} - {result['error']}{Style.RESET_ALL}")
                logger.warning(f"{domain} - {result['error']}")
                summary['dns_fail'].append(domain)
                continue

            print_status(domain, result['http'], result['ping'], result['ports'])

            if result['http'][0]:
                summary['up'].append(domain)
                if result['http'][2]:
                    summary['http_response_times'].append(result['http'][2])
            else:
                summary['down'].append(domain)

    # Report finale
    print(f"{Style.BRIGHT}Summary Report:")
    print(f"  Domains UP: {len(summary['up'])}")
    for d in summary['up']:
        print(f"    - {d}")
    print(f"  Domains DOWN or unreachable: {len(summary['down'])}")
    for d in summary['down']:
        print(f"    - {d}")
    if summary['dns_fail']:
        print(f"  DNS resolution failed: {len(summary['dns_fail'])}")
        for d in summary['dns_fail']:
            print(f"    - {d}")

    if summary['http_response_times']:
        avg_response = sum(summary['http_response_times']) / len(summary['http_response_times'])
        print(f"\nAverage HTTP response time for UP domains: {avg_response:.2f}s")
    else:
        print("\nNo HTTP responses recorded.")


if __name__ == '__main__':
    main()

