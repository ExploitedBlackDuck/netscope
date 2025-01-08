import asyncio
import nmap
import argparse
import json
import logging
from typing import List, Dict, Any


class AsyncNetworkScanner:
    """
    Asynchronous Network Scanner using Nmap for host discovery, port scanning, and optional vulnerability scanning.
    """

    def __init__(self, network_range: str, port_range: str = "1-65535", vuln_scan: bool = False):
        """
        Initialize the AsyncNetworkScanner.

        Args:
            network_range (str): Network range to scan (e.g., '192.168.1.0/24').
            port_range (str): Range of ports to scan (default: '1-65535').
            vuln_scan (bool): Enable vulnerability scanning.
        """
        self.network_range = network_range
        self.port_range = port_range
        self.vuln_scan = vuln_scan
        self.scanner = nmap.PortScanner()
        self.results = {}

    async def _execute_nmap(self, *args: Any) -> None:
        """
        Execute an Nmap scan asynchronously.

        Args:
            *args: Nmap scan arguments.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.scanner.scan, *args)

    async def discover_hosts(self) -> List[str]:
        """
        Discover active hosts in the specified network range.

        Returns:
            List[str]: A list of active hosts.
        """
        logging.info(f"Discovering active hosts in range: {self.network_range}")
        await self._execute_nmap(self.network_range, "-sn")
        active_hosts = [host for host in self.scanner.all_hosts() if self.scanner[host].state() == "up"]
        logging.info(f"Active hosts discovered: {active_hosts}")
        return active_hosts

    async def scan_ports(self, host: str) -> List[int]:
        """
        Scan open ports on a host.

        Args:
            host (str): Host to scan.

        Returns:
            List[int]: List of open ports.
        """
        logging.info(f"Scanning open ports on host: {host}")
        await self._execute_nmap(host, f"-p {self.port_range}")
        open_ports = [
            port for port, details in self.scanner[host].get("tcp", {}).items()
            if details["state"] == "open"
        ]
        logging.info(f"Open ports on {host}: {open_ports}")
        return open_ports

    async def scan_vulnerabilities(self, host: str) -> List[Dict[str, str]]:
        """
        Scan a host for vulnerabilities.

        Args:
            host (str): Host to scan.

        Returns:
            List[Dict[str, str]]: List of detected vulnerabilities.
        """
        if not self.vuln_scan:
            return []

        logging.info(f"Scanning vulnerabilities on host: {host}")
        await self._execute_nmap(host, "--script vuln")
        vulnerabilities = self.scanner[host].get("hostscript", [])
        vuln_details = [{"id": vuln["id"], "output": vuln["output"]} for vuln in vulnerabilities]
        logging.info(f"Vulnerabilities on {host}: {vuln_details}")
        return vuln_details

    async def scan_host(self, host: str) -> Dict[str, Any]:
        """
        Scan a single host for open ports and vulnerabilities.

        Args:
            host (str): Host to scan.

        Returns:
            Dict[str, Any]: Scan results for the host.
        """
        return {
            "open_ports": await self.scan_ports(host),
            "vulnerabilities": await self.scan_vulnerabilities(host) if self.vuln_scan else []
        }

    async def run_scan(self) -> Dict[str, Dict[str, Any]]:
        """
        Execute the entire scanning process.

        Returns:
            Dict[str, Dict[str, Any]]: Consolidated scan results for all hosts.
        """
        logging.info("Starting network scan...")
        active_hosts = await self.discover_hosts()
        if not active_hosts:
            logging.warning("No active hosts found.")
            return {}

        tasks = [self.scan_host(host) for host in active_hosts]
        self.results = dict(zip(active_hosts, await asyncio.gather(*tasks)))
        return self.results


def setup_logging():
    """
    Configure logging for the application.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("network_scan.log")],
    )
    logging.info("Logging setup complete.")


def save_results_to_file(results: Dict[str, Any], output_file: str):
    """
    Save scan results to a JSON file.

    Args:
        results (Dict[str, Any]): Results to save.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, "w") as file:
            json.dump(results, file, indent=4)
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving results: {e}")


async def main():
    """
    Main entry point for the network scanner.
    """
    parser = argparse.ArgumentParser(description="Asynchronous Network Scanner")
    parser.add_argument("network_range", help="Network range to scan (e.g., '192.168.1.0/24')")
    parser.add_argument("-p", "--port_range", default="1-65535", help="Port range to scan (default: 1-65535)")
    parser.add_argument("-v", "--vuln_scan", action="store_true", help="Enable vulnerability scanning")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output file for scan results")

    args = parser.parse_args()

    setup_logging()

    scanner = AsyncNetworkScanner(
        network_range=args.network_range,
        port_range=args.port_range,
        vuln_scan=args.vuln_scan,
    )

    try:
        results = await scanner.run_scan()
        save_results_to_file(results, args.output)

        # Display results
        print("\nScan Results:")
        for host, details in results.items():
            print(f"\nHost: {host}")
            print(f"  Open Ports: {details['open_ports']}")
            if details["vulnerabilities"]:
                print("  Vulnerabilities:")
                for vuln in details["vulnerabilities"]:
                    print(f"    - {vuln['id']}: {vuln['output']}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
