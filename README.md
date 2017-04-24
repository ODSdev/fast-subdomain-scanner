# Fast subdomain scanner

Very fast subdomain enumerator through DNS bruteforce, using PHP nonblocking sockets and custom DNS protocol parser implementation.

## Author

Written by Daniel Fernandez (daniel.f@opendatasecurity.io) ([@dj-thd](https://github.com/dj-thd))

## Requirements

Currently, the script is designed to run under the latest PHP version until the moment that is PHP 7.1, but if needed you should be able to adapt it to work on lower versions by removing the PHP 7.1 specific features where applicable or replacing them by equivalents in lower versions (i.e. type hinting could be removed without altering the script functionality).

## Usage

```
php fastenum.php (-wordlist ?)+ (-resolvers ?)+ (-domain ?)+ (-t ?)* [-timeout ?] [-qps ?] [-no-print-stats] [-help]
```

### Mandatory settings:
 * `-wordlist`: Wordlist file to bruteforce subdomains
 * `-resolvers`: File that contain DNS resolver IP addresses to allow parallel queries to many servers at once
 * `-domain`: Base domain to generate subdomain names

### Optional settings:
 * `-timeout`: Timeout to wait for DNS replies before retrying query, in seconds (Default: 0.5)
 * `-qps`: Maximum queries to do per second (Default: 2000)
 * `-t`: DNS query types to do (Default: A)
 * `-no-print-stats`: Do not print stats at the end (Default: print stats)
 * `-help`: Display this help only

The `-wordlist`, `-resolvers`, `-domain` and `-t` parameters may be repeated to allow multiple values.
