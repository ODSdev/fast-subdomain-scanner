MMP"""""YMM                               M""""""'YMM            dP            
M' .mmm. `M                               M  mmmm. `M            88            
M  MMMMM  M 88d888b. .d8888b. 88d888b.    M  MMMMM  M .d8888b. d8888P .d8888b. 
M  MMMMM  M 88'  `88 88ooood8 88'  `88    M  MMMMM  M 88'  `88   88   88'  `88 
M. `MMM' .M 88.  .88 88.  ... 88    88    M  MMMM' .M 88.  .88   88   88.  .88 
MMb     dMM 88Y888P' `88888P' dP    dP    M       .MM `88888P8   dP   `88888P8 
MMMMMMMMMMM 88                            MMMMMMMMMMM                          
            dP                                                                 
      MP""""""`MM                                     oo   dP            
      M  mmmmm..M                                          88            
      M.      `YM .d8888b. .d8888b. dP    dP 88d888b. dP d8888P dP    dP 
      MMMMMMM.  M 88ooood8 88'  `"" 88    88 88'  `88 88   88   88    88 
      M. .MMM'  M 88.  ... 88.  ... 88.  .88 88       88   88   88.  .88 
      Mb.     .dM `88888P' `88888P' `88888P' dP       dP   dP   `8888P88 
      MMMMMMMMMMM                                                    .88 
                                                                 d8888P  
                     MM""""""""`M MP""""""`MM MP""""""`MM 
                     MM  mmmmmmmM M  mmmmm..M M  mmmmm..M 
                     M'      MMMM M.      `YM M.      `YM 
                     MM  MMMMMMMM MMMMMMM.  M MMMMMMM.  M 
                     MM  MMMMMMMM M. .MMM'  M M. .MMM'  M 
                     MM  MMMMMMMM Mb.     .dM Mb.     .dM 

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
