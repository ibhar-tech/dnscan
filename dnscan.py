#!/usr/bin/env python3
#
# dnscan - Modernized and Async version
#

import argparse
import asyncio
import os
import re
import sys
import time
import warnings
from ipaddress import ip_address
import typing

import aiodns
import dns.resolver
import dns.query
import dns.zone
import dns.dnssec
import dns.rdatatype
import dns.name
import dns.message
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

class DNScanner:
    def __init__(self, args):
        self.args = args
        self.wildcards: typing.Dict[str, typing.List[str]] = {}
        self.addresses: typing.Set[str] = set()
        self.found_domains: typing.List[typing.Tuple[str, str]] = []
        
        self.outfile = open(args.output_filename, "w") if args.output_filename else None
        self.outfile_ips = open(args.output_ips, "w") if args.output_ips else None
        
        self.wordlist = self._load_wordlist()
        self.targets = self._load_targets()
        
        self.resolver = None
        self.sync_resolver = dns.resolver.Resolver()
        self.sync_resolver.timeout = 2
        self.sync_resolver.lifetime = 2
        self.nameservers = self._get_nameservers()
        if self.nameservers:
            self.sync_resolver.nameservers = self.nameservers

        self.record_type = 'AAAA' if args.ipv6 else 'NS' if args.tld else 'A'
        self.queue = asyncio.Queue()
        self.concurrency = args.threads * 20  # Boost concurrency since we use async
        self.progress = None
        self.task_id = None

    def _load_wordlist(self):
        wordlist_path = self.args.wordlist
        if self.args.tld and not wordlist_path:
            wordlist_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tlds.txt")
        elif not wordlist_path:
            wordlist_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "subdomains.txt")
            
        try:
            with open(wordlist_path, 'r') as f:
                return f.read().splitlines()
        except FileNotFoundError:
            console.print(f"[red]FATAL: Could not open wordlist {wordlist_path}[/red]")
            sys.exit(1)

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

    def _get_nameservers(self):
        if self.args.resolver_list:
            try:
                with open(self.args.resolver_list, 'r') as f:
                    return f.read().splitlines()
            except FileNotFoundError:
                console.print(f"[red]FATAL: Could not open file containing resolvers: {self.args.resolver_list}[/red]")
                sys.exit(1)
        elif self.args.resolvers:
            return self.args.resolvers.split(",")
        return None

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
            finally:
                if self.progress and self.task_id is not None:
                    self.progress.update(self.task_id, advance=1)
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
        self.resolver = aiodns.DNSResolver(nameservers=self.nameservers)
        
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
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as self.progress:
            self.task_id = self.progress.add_task("[cyan]Brute forcing...", total=total_tasks)
            
            workers = [asyncio.create_task(self._worker()) for _ in range(self.concurrency)]
            await asyncio.gather(*workers)
        
        if self.outfile_ips:
            for address in sorted(self.addresses):
                self.outfile_ips.write(f"{address}\n")

def get_args():
    parser = argparse.ArgumentParser(
        description='dnscan - Fast Async DNS Scanner',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40),
        epilog="Specify a custom insertion point with %% in the domain name, such as: dnscan.py -d dev-%%.example.org"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('-d', '--domain', help='Target domains (separated by commas)', dest='domain', required=False)
    target.add_argument('-l', '--list', help='File containing list of target domains', dest='domain_list', required=False)
    parser.add_argument('-w', '--wordlist', help='Wordlist', dest='wordlist', required=False)
    parser.add_argument('-t', '--threads', help='Concurrency multiplier (tasks = threads * 20)', dest='threads', required=False, type=int, default=25)
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
    args = get_args()
    try:
        scanner = DNScanner(args)
        asyncio.run(scanner.scan())
    except KeyboardInterrupt:
        console.print("\n[red]Caught KeyboardInterrupt, quitting...[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
