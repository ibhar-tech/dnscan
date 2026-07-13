#!/usr/bin/env python3
#
# dnscan - Modernized and Async version
#

import argparse
import asyncio
import uvloop
import os
import re
import sys
import time
import warnings
from ipaddress import ip_address

import aiodns
import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.rdatatype
import dns.name
import dns.message
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn, TimeRemainingColumn, ProgressColumn
from rich.text import Text
from rich.prompt import Prompt
import glob
import tempfile
import gzip

console = Console()

class SpeedColumn(ProgressColumn):
    def render(self, task):
        speed = task.speed
        if speed is None:
            return Text("? w/s", style="cyan")
        return Text(f"{speed:.1f} w/s", style="cyan")

class DNScanner:
    def __init__(self, args):
        self.args = args
        self.wildcards: dict[str, list[str]] = {}
        self.addresses: set[str] = set()
        self.found_domains: list[tuple[str, str]] = []
        
        self.outfile = open(args.output_filename, "w") if args.output_filename else None
        self.outfile_ips = open(args.output_ips, "w") if args.output_ips else None
        
        self.wordlist = self._load_wordlist()
        self.targets = self._load_targets()
        
        self.resolver = None
        self.sync_resolver = dns.resolver.Resolver()
        self.sync_resolver.timeout = 2
        self.sync_resolver.lifetime = 2
        self.record_type = 'AAAA' if self.args.ipv6 else 'A'
        
        # Default public fast resolvers to prevent ISP rate limiting
        self.nameservers = [
            '1.1.1.1', '1.0.0.1',           # Cloudflare
            '8.8.8.8', '8.8.4.4',           # Google
            '9.9.9.9', '149.112.112.112',   # Quad9
            '208.67.222.222', '208.67.220.220' # OpenDNS
        ]
        
        if args.resolvers:
            self.nameservers = args.resolvers.split(',')
        elif args.resolver_list:
            with open(args.resolver_list, 'r') as f:
                self.nameservers = [line.strip() for line in f if line.strip()]

        # Increase multiplier to maximize async socket throughput
        self.queue = asyncio.Queue()
        self.concurrency = args.threads * 100  # Boost concurrency since we use async
        self.progress = None
        self.task_id = None

    def _load_wordlist(self):
        data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
        
        def read_lines(path):
            if path.endswith('.gz'):
                with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as f:
                    return f.read().splitlines()
            else:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read().splitlines()
        
        # If user provided a specific path via -w
        if self.args.wordlist:
            if os.path.exists(self.args.wordlist):
                return read_lines(self.args.wordlist)
            else:
                # Try in data dir
                potential_path = os.path.join(data_dir, self.args.wordlist)
                if os.path.exists(potential_path):
                    return read_lines(potential_path)
                console.print(f"[red]FATAL: Could not open wordlist {self.args.wordlist}[/red]")
                sys.exit(1)
                
        # If user provided a size argument via positional (e.g. 100)
        if hasattr(self.args, 'wordlist_size') and self.args.wordlist_size:
            size_arg = self.args.wordlist_size
            
            # Check for possible filenames (with .txt or .txt.gz)
            possible_filenames = [
                f"subdomains-{size_arg}.txt",
                f"subdomains-{size_arg}.txt.gz",
                size_arg,
                f"{size_arg}.gz"
            ]
            
            for filename in possible_filenames:
                potential_path = os.path.join(data_dir, filename)
                if os.path.exists(potential_path):
                    return read_lines(potential_path)
            
            # If not found, fall back to error
            console.print(f"[red]FATAL: Could not find wordlist matching '{size_arg}' in {data_dir}[/red]")
            sys.exit(1)

        # Handle TLD mode natively if requested
        if self.args.tld:
            tld_path = os.path.join(data_dir, "tlds.txt")
            if os.path.exists(tld_path):
                return read_lines(tld_path)
                    
        # Interactive mode if no wordlist is provided
        console.print("[cyan]No wordlist provided. Available wordlists in data folder:[/cyan]")
        available_lists = sorted(glob.glob(os.path.join(data_dir, "*.txt")) + glob.glob(os.path.join(data_dir, "*.txt.gz")))
        if not available_lists:
            console.print("[red]FATAL: No wordlists found in data folder.[/red]")
            sys.exit(1)
            
        for idx, path in enumerate(available_lists, 1):
            size_bytes = os.path.getsize(path)
            size_mb = size_bytes / (1024 * 1024)
            size_str = f"{size_mb:.2f} MB" if size_mb > 1 else f"{size_bytes / 1024:.2f} KB"
            console.print(f"  [green]{idx}[/green] - {os.path.basename(path)} ({size_str})")
            
        console.print("[dim]You can choose multiple wordlists by separating them with commas (e.g., 1,3,5), or type 'all' to use all of them[/dim]")
        choices = Prompt.ask("Select wordlists", default="1")
        
        selected_paths = []
        if choices.strip().lower() == 'all':
            selected_paths = available_lists
        else:
            for choice in choices.split(','):
                choice = choice.strip()
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(available_lists):
                        selected_paths.append(available_lists[idx])
        
        if not selected_paths:
            console.print("[red]FATAL: No valid wordlists selected.[/red]")
            sys.exit(1)
            
        combined_words = set()
        for path in selected_paths:
            combined_words.update(filter(bool, read_lines(path)))
                
        # Write to a physical temporary file so the user has it if they need to inspect it
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="dnscan_wordlist_", suffix=".txt", text=True)
        with os.fdopen(tmp_fd, 'w') as f:
            for word in combined_words:
                f.write(word + '\n')
                
        console.print(f"[blue][*][/blue] Combined {len(selected_paths)} wordlists into temporary file:")
        console.print(f"    [yellow]{tmp_path}[/yellow] ([green]{len(combined_words)} unique words[/green])")
        
        return list(combined_words)

    def _load_targets(self):
        targets = []
        if self.args.domain:
            targets.extend(self.args.domain.split(","))
        if self.args.domain_list:
            try:
                with open(self.args.domain_list, 'r') as f:
                    targets.extend(list(filter(bool, f.read().split('\n'))))
            except Exception as e:
                console.print(f"[red]FATAL: Couldn't read {self.args.domain_list}: {e}[/red]")
                sys.exit(1)
        if not targets:
            console.print("[red]FATAL: No targets specified.[/red]")
            sys.exit(1)
        return targets


    def output_status(self, msg):
        console.print(f"[blue][*][/blue] {msg}")
        if self.outfile and not self.args.quick:
            self.outfile.write(f"[*] {msg}\n")

    def output_good(self, msg):
        console.print(f"[green][+][/green] {msg}")
        if self.outfile and not self.args.quick:
            self.outfile.write(f"[+] {msg}\n")

    def output_warn(self, msg):
        console.print(f"[red][-][/red] {msg}")
        if self.outfile and not self.args.quick:
            self.outfile.write(f"[-] {msg}\n")
            
    def output_result(self, domain, address):
        if self.args.no_ip:
            console.print(f"[yellow]{domain}[/yellow]")
        elif self.args.domain_first:
            console.print(f"{domain} - [yellow]{address}[/yellow]")
        else:
            console.print(f"{address} - [yellow]{domain}[/yellow]")
            
        if self.outfile:
            if self.args.domain_first:
                self.outfile.write(f"{domain} - {address}\n")
            else:
                self.outfile.write(f"{address} - {domain}\n")
                
        try:
            # Validate IP
            ip_address(address)
            self.addresses.add(address)
        except ValueError:
            pass

    async def get_wildcard(self, target):
        epochtime = str(int(time.time()))
        test_domain = f"a{epochtime}.{target}"
        wildcards = []
        try:
            res = await self.resolver.query(test_domain, self.record_type)
            for rdata in res:
                wildcards.append(rdata.host)
            if wildcards:
                self.output_warn(f"Wildcard domain found - [yellow]*.{target}[/yellow] ({', '.join(wildcards)})")
        except aiodns.error.DNSError:
            if self.args.verbose:
                console.print(f"[dim][v] No wildcard domain found for {target}[/dim]")
        self.wildcards[target] = wildcards
        return wildcards

    def check_zone_transfer(self, domain, ns, nsip):
        if self.args.verbose:
            console.print(f"[dim][v] Trying zone transfer against {ns}[/dim]")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(str(nsip), domain, relativize=False, timeout=1, lifetime=2), relativize=False)
            self.output_good(f"Zone transfer successful using nameserver [yellow]{ns}[/yellow]")
            names = list(zone.nodes.keys())
            names.sort()
            for n in names:
                txt = zone[n].to_text(n)
                console.print(txt)
                if self.outfile:
                    self.outfile.write(f"{txt}\n")
            if self.args.zonetransfer:
                sys.exit(0)
        except Exception:
            pass

    def check_v6(self, target):
        if self.args.verbose:
            console.print("[dim][v] Getting IPv6 (AAAA) records[/dim]")
        try:
            res = self.sync_resolver.resolve(target, "AAAA")
            if res:
                self.output_good("IPv6 (AAAA) records found.")
            for v6 in res:
                console.print(str(v6))
                if self.outfile:
                    self.outfile.write(f"{v6}\n")
        except Exception:
            pass

    def check_txt(self, target):
        if self.args.verbose:
            console.print("[dim][v] Getting TXT records[/dim]")
        try:
            res = self.sync_resolver.resolve(target, "TXT")
            if res:
                self.output_good("TXT records found")
            for txt in res:
                console.print(txt.to_text())
                if self.outfile:
                    self.outfile.write(f"{txt.to_text()}\n")
        except Exception:
            pass

    def check_dmarc(self, target):
        if self.args.verbose:
            console.print("[dim][v] Getting DMARC records[/dim]")
        try:
            res = self.sync_resolver.resolve(f"_dmarc.{target}", "TXT")
            if res:
                self.output_good("DMARC records found")
            for dmarc in res:
                console.print(dmarc.to_text())
                if self.outfile:
                    self.outfile.write(f"{dmarc.to_text()}\n")
        except Exception:
            pass

    def check_dnssec(self, target, nameserver):
        if self.args.verbose:
            console.print("[dim][v] Checking DNSSEC[/dim]")
        try:
            request = dns.message.make_query(target, dns.rdatatype.DNSKEY, want_dnssec=True)
            response = dns.query.udp(request, nameserver, timeout=2)
            if response.rcode() != 0:
                self.output_warn(f"DNSKEY lookup returned error code {dns.rcode.to_text(response.rcode())}")
            else:
                answer = response.answer
                if len(answer) == 0:
                    self.output_warn("DNSSEC not supported")
                elif len(answer) != 2:
                    self.output_warn("Invalid DNSKEY record length")
                else:
                    name = dns.name.from_text(target)
                    try:
                        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
                    except dns.dnssec.ValidationFailure:
                        self.output_warn("DNSSEC key validation failed")
                    else:
                        self.output_good("DNSSEC enabled and validated")
                        dnssec_values = str(answer[0][0]).split(' ')
                        algorithm_int = int(dnssec_values[2])
                        algorithm_str = dns.dnssec.algorithm_to_text(algorithm_int)
                        console.print(f"Algorithm = {algorithm_str} ({algorithm_int})")
        except Exception as e:
            if self.args.verbose:
                console.print(f"[dim][v] DNSSEC Check Error: {e}[/dim]")

    def check_mx(self, target):
        if self.args.verbose:
            console.print("[dim][v] Getting MX records[/dim]")
        try:
            res = self.sync_resolver.resolve(target, "MX")
            if res:
                self.output_good("MX records found, added to target list")
            for mx in res:
                console.print(mx.to_text())
                if self.outfile:
                    self.outfile.write(f"{mx.to_text()}\n")
                
                # Check for subdomains in MX
                mxsub = re.search(rf'([a-z0-9.-]+)\.{re.escape(target)}', mx.to_text(), re.IGNORECASE)
                if mxsub and mxsub.group(1) and mxsub.group(1) not in self.wordlist:
                    self.queue.put_nowait((f"{mxsub.group(1)}.{target}", target, 0))
        except Exception:
            pass

    async def _worker(self):
        while True:
            try:
                domain, base_target, depth = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            try:
                res = await self.resolver.query(domain, self.record_type)
                
                valid_responses = []
                for rdata in res:
                    address = rdata.host
                    # Filter out wildcard IPs
                    if base_target in self.wildcards and address in self.wildcards[base_target]:
                        continue
                    valid_responses.append(address)
                
                if self.args.tld and res:
                    # TLD mode special formatting
                    sorted_ns = sorted(valid_responses)
                    if sorted_ns:
                        self.output_result(domain, sorted_ns[0])
                else:
                    for address in valid_responses:
                        self.output_result(domain, address)
                
                if valid_responses and self.args.recurse and depth < self.args.maxdepth and domain != base_target:
                    # Recursively scan found subdomain
                    wc = await self.get_wildcard(domain)
                    if self.args.recurse_wildcards or not wc:
                        self._populate_queue(domain, base_target, depth + 1)
                        if self.progress and self.task_id is not None:
                            self.progress.update(self.task_id, total=self.queue.qsize() + self.progress.tasks[self.task_id].completed)

            except aiodns.error.DNSError:
                pass
            except Exception as e:
                if self.args.verbose:
                    console.print(f"[dim][v] Worker error for {domain}: {e}[/dim]")
            finally:
                self.queue.task_done()

    def _populate_queue(self, domain, base_target, depth):
        for word in self.wordlist:
            patterns = [word]
            if self.args.alt:
                probes = ["dev", "prod", "stg", "qa", "uat", "api", "alpha", "beta",
                          "cms", "test", "internal", "staging", "origin", "stage"]
                for probe in probes:
                    if probe not in word:
                        patterns.extend([f"{probe}{word}", f"{word}{probe}", f"{probe}-{word}", f"{word}-{probe}"])
                if not word[-1].isdigit():
                    for n in range(1, 6):
                        patterns.extend([f"{word}{n}", f"{word}0{n}"])
            
            for pattern in patterns:
                if '%%' in domain:
                    new_domain = domain.replace('%%', pattern)
                else:
                    new_domain = f"{pattern}.{domain}"
                self.queue.put_nowait((new_domain, base_target, depth))

    async def scan(self):
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        self.resolver = aiodns.DNSResolver(nameservers=self.nameservers, tries=1, timeout=1.5, rotate=True)
        
        # Baseline checks
        if not self.args.nocheck:
            try:
                self.sync_resolver.resolve('.', 'NS')
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NoNameservers:
                self.output_warn("Failed to resolve '.' - server may be buggy. Continuing anyway....")
            except Exception:
                console.print("[red]FATAL: No valid DNS resolver. This can occur when the server only resolves internal zones[/red]")
                console.print("[red]Set a custom resolver with -R <resolver>[/red]")
                console.print("[red]Ignore this warning with -n / --nocheck[/red]")
                sys.exit(1)

        for target in self.targets:
            self.output_status(f"Processing domain [yellow]{target}[/yellow]")
            
            if self.args.tld and '%%' not in target:
                if "." in target:
                    self.output_warn("Warning: TLD scanning works best with just the domain root")
                self.output_good("TLD Scan")
                for tld in self.wordlist:
                    self.queue.put_nowait((f"{target}.{tld}", target, 0))
            else:
                # Basic domain baseline checks
                self.queue.put_nowait((target, target, 0))
                
                if '%%' not in target:
                    self.output_good("Getting nameservers")
                    nsip = None
                    try:
                        nameservers = self.sync_resolver.resolve(target, 'NS')
                        for ns in nameservers:
                            ns_str = str(ns).rstrip('.')
                            try:
                                res = self.sync_resolver.resolve(ns_str, "A")
                                for rdata in res:
                                    nsip = str(rdata.address)
                                    console.print(f"{nsip} - [yellow]{ns_str}[/yellow]")
                                    if not self.args.quick and self.outfile:
                                        self.outfile.write(f"{nsip} - {ns_str}\n")
                                self.check_zone_transfer(target, ns_str, nsip)
                            except Exception:
                                pass
                    except Exception:
                        self.output_warn("Getting nameservers failed")
                    
                    if not self.args.quick:
                        self.check_v6(target)
                        self.check_txt(target)
                        self.check_dmarc(target)
                        
                        if nsip:
                            self.check_dnssec(target, nsip)
                        elif self.sync_resolver.nameservers:
                            self.check_dnssec(target, self.sync_resolver.nameservers[0])
                        self.check_mx(target)
                
                await self.get_wildcard(target)
                self.output_status(f"Scanning [yellow]{target}[/yellow] for {self.record_type} records")
                self._populate_queue(target, target, 0)
        
        if self.queue.empty():
            return

        total_tasks = self.queue.qsize()
        console.print(f"[blue][*][/blue] Starting brute force with [yellow]{self.args.threads}[/yellow] threads (Concurrency: [yellow]{self.concurrency}[/yellow] concurrent tasks)")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            MofNCompleteColumn(),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            SpeedColumn(),
            TimeElapsedColumn(),
            TextColumn("ETA:"),
            TimeRemainingColumn(),
            console=console
        ) as self.progress:
            self.task_id = self.progress.add_task("[cyan]Brute forcing...", total=total_tasks)
            
            async def update_progress():
                while not self.queue.empty():
                    completed = total_tasks - self.queue.qsize()
                    self.progress.update(self.task_id, completed=completed)
                    await asyncio.sleep(0.5)
                self.progress.update(self.task_id, completed=total_tasks)
                
            progress_task = asyncio.create_task(update_progress())
            workers = [asyncio.create_task(self._worker()) for _ in range(self.concurrency)]
            await asyncio.gather(*workers)
            await progress_task
        
        if self.outfile_ips:
            for address in sorted(self.addresses):
                self.outfile_ips.write(f"{address}\n")

    def cleanup(self):
        """Close any open output files."""
        if self.outfile:
            self.outfile.close()
        if self.outfile_ips:
            self.outfile_ips.close()

def get_args():
    parser = argparse.ArgumentParser(
        description='dnscan - Fast Async DNS Scanner',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
        epilog="Specify a custom insertion point with %% in the domain name, such as: dnscan.py -d dev-%%.example.org"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('-d', '--domain', help='Target domains (separated by commas)', dest='domain', required=False)
    target.add_argument('-l', '--list', help='File containing list of target domains', dest='domain_list', required=False)
    parser.add_argument('wordlist_size', nargs='?', help='Size of the built-in wordlist to use (e.g., 100, 500, 1000)', default=None)
    parser.add_argument('-w', '--wordlist', help='Wordlist', dest='wordlist', required=False)
    parser.add_argument('-t', '--threads', help='Concurrency multiplier (tasks = threads * 100)', dest='threads', required=False, type=int, default=25)
    parser.add_argument('-6', '--ipv6', action="store_true", help='Scan for AAAA records', dest='ipv6')
    parser.add_argument('-z', '--zonetransfer', action="store_true", help='Only perform zone transfers', dest='zonetransfer')
    parser.add_argument('-r', '--recursive', action="store_true", help="Recursively scan subdomains", dest='recurse')
    parser.add_argument('--recurse-wildcards', action="store_true", help="Recursively scan wildcards (slow)", dest='recurse_wildcards')
    parser.add_argument('-m', '--maxdepth', help='Maximal recursion depth (for brute-forcing)', dest='maxdepth', required=False, type=int, default=5)
    parser.add_argument('-a', '--alterations', action="store_true", help='Scan for alterations of subdomains (slow)', dest='alt')
    parser.add_argument('-R', '--resolver', help="Use the specified resolvers (separated by commas)", dest='resolvers', required=False)
    parser.add_argument('-L', '--resolver-list', help="File containing list of resolvers", dest='resolver_list', required=False)
    parser.add_argument('-T', '--tld', action="store_true", help="Scan for TLDs", dest='tld')
    parser.add_argument('-o', '--output', help="Write output to a file", dest='output_filename', required=False)
    parser.add_argument('-i', '--output-ips', help="Write discovered IP addresses to a file", dest='output_ips', required=False)
    parser.add_argument('-D', '--domain-first', action="store_true", help='Output domain first, rather than IP address', dest='domain_first')
    parser.add_argument('-N', '--no-ip', action="store_true", help='Don\'t print IP addresses in the output', dest='no_ip')
    parser.add_argument('-v', '--verbose', action="store_true", help='Verbose mode', dest='verbose')
    parser.add_argument('-n', '--nocheck', action="store_true", help='Don\'t check nameservers before scanning', dest='nocheck')
    parser.add_argument('-q', '--quick', action="store_true", help='Only perform zone transfer and subdomains scan, with minimal output to file', dest='quick')
    return parser.parse_args()

def main():
    uvloop.install()
    args = get_args()
    scanner = None
    try:
        scanner = DNScanner(args)
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        console.print("\n[red]Caught KeyboardInterrupt, quitting...[/red]")
        sys.exit(1)
    finally:
        if scanner:
            scanner.cleanup()

if __name__ == "__main__":
    main()
