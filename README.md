dnscan
======

dnscan is a python wordlist-based DNS subdomain scanner.

The script will first try to perform a zone transfer using each of the target domain's nameservers.

If this fails, it will lookup TXT and MX records for the domain, and then perform a recursive subdomain scan using the supplied wordlist.

### Modern Upgrade

This tool has been thoroughly modernized to use **`uv`** for dependency management, **`asyncio`** and **`aiodns`** for blazing-fast asynchronous DNS resolution, and **`rich`** for a beautiful terminal UI with progress bars.

Usage
-----

```
uv run ./dnscan.py (-d <domain> | -l <list>) [wordlist_size] [OPTIONS]
```

#### Mandatory Arguments
    -d  --domain                              Target domain; OR
    -l  --list                                Newline separated file of domains to scan
    
#### Optional Arguments
    wordlist_size                             Size of the built-in wordlist to use (e.g., 100, 500, 1000)
    -w --wordlist <wordlist>                  Wordlist of subdomains to use
    -t --threads <threadcount>                Concurrency multiplier (tasks = threads * 20), default 25
    -6 --ipv6                                 Scan for IPv6 records (AAAA)
    -z --zonetransfer                         Perform zone transfer and exit
    -r --recursive                            Recursively scan subdomains
       --recurse-wildcards                    Recursively scan wildcards (slow)

    -m --maxdepth                             Maximum levels to scan recursively
    -a --alterations                          Scan for alterations of subdomains (slow)
    -R --resolver <resolver>                  Use the specified resolver instead of the system default
    -L --resolver-list <file>                 Read list of resolvers from a file
    -T --tld                                  Scan for the domain in all TLDs
    -o --output <filename>                    Output to a text file
    -i --output-ips <filename>                Output discovered IP addresses to a text file
    -n --nocheck                              Don't check nameservers before scanning. Useful in airgapped networks
    -q --quick                                Only perform the zone transfer and subdomain scans. Suppresses most file output with -o
    -N --no-ip                                Don't print IP addresses in the output
    -v --verbose                              Verbose output
    -h --help                                 Display help text

Custom insertion points can be specified by adding `%%` in the domain name, such as:

```
$ uv run ./dnscan.py -d dev-%%.example.org
```

Wordlists
---------

A number of wordlists are supplied with dnscan.

You can use the positional `wordlist_size` shortcut to easily select a built-in wordlist without the `-w` flag.
For example, `uv run ./dnscan.py -d example.com 100` uses `subdomains-100.txt`.

The first four (**subdomains-100.txt**, **subdomains-500.txt**, **subdomains-1000.txt** and **subdomains-10000.txt**) were created by analysing the most commonly occuring subdomains in approximately 86,000 zone files that were transferred as part of a separate research project. These wordlists are sorted by the popularity of the subdomains (more strictly by the percentage of zones that contained them in the dataset).

The **subdomains-uk-500.txt** and **subdomains-uk-1000.txt** lists are created using the same methodology, but from a set of approximately 180,000 zone transfers from ".uk" domains.

The final (and default) wordlist (**subdomains.txt**) is based on the top 500 subdomains by popularity and the top 500 UK subdomains, but has had a number of manual additions made based on domains identified during testing.

This list is sorted alphabetically and currently contains approximately **770** entries.


TLD Scanning
------------
The -T (--tld) option can be used to scan for all of the TLDs a specific domain name exists in. By default it will use the **tlds.txt** list, which contains all of the TLDs listed by IANA (including new TLDs). You can also specify a custom wordlist with -w. The **suffixes.txt** file included is a cut-down version of the public suffix list, so will include most of the second level domains (such as co.uk).

Note that when you use this option, you should only specify the base of the domain name ("github", not "github.com").

Alterations
-----------
The `-a`/`--alterations` switch adds various prefixes and suffixes (such as `dev`, `test`, `01`, etc) to the domains, with and without hyphens. This generates **a lot** of extra permutations (approximately 60 permutations per domain), so is much slower, especially with larger wordlists.


Setup
-----

dnscan requires Python 3.12+ and uses `uv` for dependency management. It relies on the `aiodns`, `dnspython`, `netaddr`, `cryptography`, `packaging`, and `rich` libraries.

Run the following command to initialize and run the tool:

    $ uv run ./dnscan.py -h
