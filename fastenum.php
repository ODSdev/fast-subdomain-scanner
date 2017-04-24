#!/usr/bin/env php
<?php

/*

Fast subdomain scanner
Very fast subdomain enumerator through DNS bruteforce, using PHP nonblocking sockets and custom DNS protocol parser implementation.

- Author:
Written by Daniel Fernandez (daniel.f@opendatasecurity.io) ([@dj-thd](https://github.com/dj-thd))

- Requirements:
Currently, the script is designed to run under the latest PHP version until the moment that is PHP 7.1, but if needed you should be able to adapt it to work on lower versions by removing the PHP 7.1 specific features where applicable or replacing them by equivalents in lower versions (i.e. type hinting could be removed without altering the script functionality).

Execute "php fastenum.php -help" for usage information.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

(c) 2017 by OpenDataSecurity (https://opendatasecurity.io)

*/

const DNS_TYPES_BY_NAME = array(
    'A' => 1,
    'NS' => 2,
    'CNAME' => 5,
    'SOA' => 6,
    'PTR' => 12,
    'MX' => 15,
    'TXT' => 16,
    'AXFR' => 252,
    'ANY' => 255 // Deprecated
);

const DNS_TYPES_BY_VALUE = array(
    1 => 'A',
    2 => 'NS',
    5 => 'CNAME',
    6 => 'SOA',
    12 => 'PTR',
    15 => 'MX',
    16 => 'TXT',
    252 => 'AXFR',
    255 => 'ANY' // Deprecated
);

// Class that parse and represent DNS strings
class DnsString
{
	protected $raw_data;
	protected $raw_index;
	protected $raw_length;
	protected $parsed = array();
	
	public function getRawLength() : int
	{
	    return $this->raw_length;
	}
	
	public function getParsed() : array
	{
	    return $this->parsed;
	}
	
	public function __construct(array $labels = array())
	{
	    $this->parsed = $labels;
	}

    // Parse raw string at index
	public function parse(string $data, int $index) : void
	{
        // Reinitialize object
        $this->__construct();

		$this->raw_data = $data;
		$this->raw_index = $index;
		$datalen = strlen($data);
		
		for($i = $index; $i < $datalen && ($len = intval(ord($data[$i])));) {
		    if($len & 0xc0) { // Parse DNS string pointer
		        $pointed_index = unpack('n', substr($data, $i, 2))[1] & 0x3FFF;
		        $pointed = new DnsString();
		        $pointed->parse($data, $pointed_index);
		        $this->parsed = array_merge($this->parsed, $pointed->parsed);
		        $i++;
		        break;
		    } else { // Parse raw DNS string
		        $i++;
    			$this->parsed[] = substr($data, $i, $len);
    			$i += $len;
    	    }
		}
		$this->raw_length = $i - $index + 1;
	}
	
    // Serialize current string and convert to raw data
	public function serialize() : string
	{
	    $result = '';
	    foreach($this->parsed as $label) {
	        $result .= chr(strlen($label));
	        $result .= $label;
	    }
	    $result .= chr(0);
	    return $result;
    }
	
    // Generate representable string
	public function __toString() : string
	{
	    return implode('.', $this->parsed);
	}
}

// Class that parse and represent a DNS question
class DnsQuestion
{
	protected $raw_data = '';
	protected $raw_index = 0;
	protected $raw_length = 0;

	protected $qname;
	protected $qtype;
	protected $qclass;
	
	public function __construct(DnsString $qname = null, int $qtype = 0, int $qclass = 1)
	{
	    $this->qname = $qname ? $qname : new DnsString();
	    $this->qtype = $qtype;
	    $this->qclass = $qclass;
	}
	
	public function getQname() : DnsString
	{
	    return $this->qname;
	}
	
	public function getQtype() : int
	{
	    return $this->qtype;
	}
	
	public function getRawLength() : int
	{
	    return $this->raw_length;
	}

	public function parse(string $data, int $index) : void
	{
        // Reinitialize object
	    $this->__construct();
	    
		$this->raw_data = $data;
		$this->raw_index = $index;
		
		$this->qname = new DnsString();
		$this->qname->parse($data, $index);
		$this->raw_length = $this->qname->getRawLength();		

		$this->qtype = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$this->qclass = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;
	}
	
	public function serialize() : string
	{
	    $result = $this->qname->serialize();
	    $result .= pack('n', $this->qtype);
	    $result .= pack('n', $this->qclass);
	    return $result;
	}
	
	public function __toString() : string
	{
        return (string)$this->qname;
	}
}

// Class that parse and represent a DNS resource record
class DnsRR extends DnsQuestion
{
	protected $ttl;
	protected $rdata;
	
	public function __construct(DnsString $qname = null, int $qtype = 0, int $qclass = 0, int $ttl = 0, string $rdata = '')
	{
	    parent::__construct($qname, $qtype, $qclass);
	    $this->ttl = 0;
	    $this->rdata = $rdata;
	}

	public function parse(string $data, int $index) : void
	{
	    $this->__construct();
	    parent::parse($data, $index);
	    
		$this->ttl = unpack('N', substr($data, $this->raw_length+$index, 4))[1];
		$this->raw_length += 4;

		$rdata_len = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$this->rdata = substr($data, $this->raw_length+$index, $rdata_len);
		$this->raw_length += $rdata_len;
	}
	
	public function serialize() : string
	{
	    $result = parent::serialize();
	    $result .= pack('N', $this->ttl);
	    $result .= pack('n', strlen($this->rdata));
	    $result .= $this->rdata;
	    return $result;
	}
	
	public function __toString() : string
	{
	    $additional = '';
	    switch($this->qtype) {
	        case 1: // A
	            $additional = ' (IP = ' . long2ip(unpack('N', $this->rdata)[1]) . ')';
	            break;
	        case 5: // CNAME
	            $dns_str = new DnsString();
	            $dns_str->parse($this->raw_data, $this->raw_index + $this->raw_length - strlen($this->rdata));
	            $additional = ' (NAME = ' . implode('.', $dns_str->getParsed()) . ')';
	            break;
	    }
	    return parent::__toString() . $additional;
	}
}

// Class that parse and represent a DNS header
class DnsHeader
{
	protected $raw_data = '';
	protected $raw_index = 0;
	protected $raw_length = 0;

	protected $query_id;
	protected $is_response;
	protected $opcode;
	protected $is_aa;
	protected $is_truncated;
	protected $is_recursion_desired;
	protected $is_recursion_available;
	protected $response_code;
	protected $qdcount;
	protected $ancount;
	protected $nscount;
	protected $arcount;
	
	public function __construct()
	{
        $this->query_id = 0;
        $this->is_response = false;
        $this->opcode = 0;
        $this->is_aa = false;
        $this->is_truncated = false;
        $this->is_recursion_desired = true;
        $this->is_recursion_available = false;
        $this->response_code = 0;

        $this->qdcount = 0;
        $this->ancount = 0;
        $this->nscount = 0;
        $this->arcount = 0;
	}
	
	public function getRawLength() : int
	{
	    return $this->raw_length;
	}
	
	public function getId() : int
	{
	    return $this->query_id;
	}
	
	public function getQdCount() : int
	{
	    return $this->qdcount;
	}
	
	public function getAnCount() : int
	{
	    return $this->ancount;
	}
	
	public function getNsCount() : int
	{
	    return $this->nscount;
	}
	
	public function getArCount() : int
	{
	    return $this->arcount;
	}
	
	public function setId(int $query_id) : void
	{
	    $this->query_id = $query_id;
	}
	
	public function setQdCount(int $qdcount) : void
	{
	    $this->qdcount = $qdcount;
	}
	
	public function setAnCount(int $ancount) : void
	{
	    $this->ancount = $ancount;
	}
	
	public function setNsCount(int $nscount) : void
	{
	    $this->nscount = $nscount;
	}
	
	public function setArCount(int $arcount) : void
	{
	    $this->arcount = $arcount;
	}

	public function parse(string $data, int $index) : void
	{
	    $this->__construct();
		
		$this->raw_length = 0;

		$this->query_id = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$flags = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$this->is_response = $flags & 0x8000 ? true : false;
		$this->opcode = (($flags & 0x7100) >> 11) & 0x000F;
		$this->is_truncated = $flags & 0x0200 ? true : false;
		$this->is_recursion_desired = $flags & 0x0100 ? true : false;
		$this->is_recursion_available = $flags & 0x0080 ? true : false;
		$this->response_code = $flags & 0x000F;

		$this->qdcount = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$this->ancount = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$this->nscount = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;

		$this->arcount = unpack('n', substr($data, $this->raw_length+$index, 2))[1];
		$this->raw_length += 2;
	}
	
	public function serialize() : string
	{
	    $result = pack('n', $this->query_id);
	    $flags = 0;
	    $flags |= $this->is_response ? 0x8000 : 0;
	    $flags |= ($this->opcode & 0xF) << 11;
	    $flags |= $this->is_truncated ? 0x0200 : 0;
	    $flags |= $this->is_recursion_desired ? 0x0100 : 0;
	    $flags |= $this->is_recursion_available ? 0x0080 : 0;
	    $flags |= $this->response_code & 0xF;
	    $result .= pack('n', $flags);
	    $result .= pack('n', $this->qdcount);
	    $result .= pack('n', $this->ancount);
	    $result .= pack('n', $this->nscount);
	    $result .= pack('n', $this->arcount);
	    return $result;
	}
	
	public function __toString() : string
	{
	    if($this->is_response) {
	        return 'RESPONSE ' . dechex($this->query_id) . ' CODE ' . dechex($this->response_code);
	    } else {
	        return 'QUERY ' . dechex($this->query_id) . ' OPCODE ' . dechex($this->opcode);
	    }
	}
}

// Class that represent and parse a DNS message
class DnsMessage
{
	protected $raw_data = '';
	protected $raw_index = 0;
	protected $raw_length = 0;

	protected $header = null;
	protected $questions = array();
	protected $answers = array();
	protected $authorities = array();
	protected $additional = array();
	
	public function __construct(DnsHeader $header = null, array $questions = array(), array $answers = array(),
	    array $authorities = array(), array $additional = array())
	{
	    $this->header = $header ? $header : new DnsHeader();
	    $this->questions = $questions;
	    $this->answers = $answers;
	    $this->authorities = $authorities;
	    $this->additional = $additional;
	    if($header) {
    	    $this->header->setQdCount = count($questions);
	        $this->header->setAnCount = count($answers);
	        $this->header->setNsCount = count($authorities);
	        $this->header->setArCount = count($additional);
	    }
	}
	
	public function getHeader() : DnsHeader
	{
	    return $this->header;
	}
	
	public function getRawLength() : int
	{
	    return $this->raw_length;
	}
	
	public function getQuestions() : array
	{
	    return $this->questions;
	}
	
	public function setQuestions(array $questions) 
	{
	    $this->questions = $questions;
	    $this->header->setQdCount(count($questions));
	}
	
	public function getAnswers() : array
	{
	    return $this->answers;
	}

	public function parse(string $data, int $index) 
    {
        $this->__construct();
        
		$this->raw_data = $data;
		$this->raw_index = $index;
		$this->raw_length = 0;

		$this->header = new DnsHeader();
		$this->header->parse($data, $index);
		$this->raw_length += $this->header->getRawLength();

		for($i = 0; $i < $this->header->getQdCount(); $i++) {
			$item = new DnsQuestion();
			$item->parse($data, $this->raw_length+$index);
			$this->questions[] = $item;
			$this->raw_length += $item->getRawLength();
        }

		for($i = 0; $i < $this->header->getAnCount(); $i++) {
			$item = new DnsRR();
			$item->parse($data, $this->raw_length+$index);
			$this->answers[] = $item;
			$this->raw_length += $item->getRawLength();
		}

		for($i = 0; $i < $this->header->getNsCount(); $i++) {
			$item = new DnsRR();
			$item->parse($data, $this->raw_length+$index);
			$this->authorities[] = $item;
			$this->raw_length += $item->getRawLength();
		}

		for($i = 0; $i < $this->header->getArCount(); $i++) {
			$item = new DnsRR();
			$item->parse($data, $this->raw_length+$index);
			$this->additional[] = $item;
			$this->raw_length += $item->getRawLength();
		}
	}
	
	public function serialize() : string
	{
	    $result = $this->header->serialize();
	    foreach(array($this->questions, $this->answers, $this->authorities, $this->additional) as $item_container) {
	        foreach($item_container as $item) {
    	        $result .= $item->serialize();
    	    }
	    }
	    return $result;
	}
	
	public function __toString() : string
	{
	    return (string)$this->header . "\n" .
	        "Questions:\n" .
	        "\t" . implode("\n\t", $this->questions) . "\n" .
	        "Answers:\n" .
	        "\t" . implode("\n\t", $this->answers) . "\n" .
	        "Authorities:\n" .
	        "\t" . implode("\n\t", $this->authorities) . "\n" .
		    "Additional:\n" .
	        "\t" . implode("\n\t", $this->additional) . "\n";
	}
}

// Class that represents a DNS query
class DnsQuery
{
    protected $message = null;
    
    public function __construct()
    {
        $this->message = new DnsMessage(new DnsHeader());
    }
    
    public function getId() : int
    {
        return $this->message->getHeader()->getId();
    }
    
    public function newQuestion(int $qtype, string $label) : void
    {
        $qname = new DnsString(explode('.', $label));
        $question = new DnsQuestion($qname, $qtype);
        $this->message->setQuestions(array($question));
        $this->message->getHeader()->setId(rand(0, 65534));
    }

    public function serialize() : string
    {
        return $this->message->serialize();
    }
}

// Helper function to search array for the first element that meets condition
function array_custom_search(array &$data, callable $callback) : \Generator
{
    while(!empty($data)) {
        // Loop array forwards
        foreach($data as $item) {
            if($callback($item)) {
                yield $item;
            }
        }
        // No item found
        yield null;

        // Then loop backwards in next iteration
        for($item = end($data); $item; $item = prev($data)) {
            if($callback($item)) {
                yield $item;
            }
        }
        // No item found
        yield null;
    }
}

function parse_arguments(array $argv, string &$error) : ?array
{
    // Default arguments
    $result = array(
        'resolvers' => array(),
        'wordlist' => array(),
        'domain' => array(),
        'timeout' => '0.5',
        'types' => array(),
        'qps' => '2000',
        'print_stats' => true
    );

    // Parse command line
    for($i = 1; $i < count($argv); $i++) {

        // Options begin with '-'
        if(strlen($argv[$i]) < 2 || $argv[$i][0] !== '-') {
            $error = sprintf("The supplied argument '%s' is not a valid option\n\n", $argv[$i]);
            return null;
        }

        // Check if option is valid
        switch(($option = substr($argv[$i], 1))) {
            case 'qps':
                if(!ctype_digit($argv[$i+1])) {
                    $error = sprintf("The supplied value for '%s' is not a valid argument\nGot: '%s', expected: digits\n\n", $argv[$i], $argv[$i+1]);
                    return null;
                }
            case 'timeout':
                if(!is_numeric($argv[$i+1])) {
                    $error = sprintf("The supplied value for '%s' is not a valid argument\nGot: '%s', expected: numeric value\n\n", $argv[$i], $argv[$i+1]);
                    return null;
                }
            case 'resolvers':
            case 'wordlist':
            case 'domain':
            case 'timeout':
            case 't':
                if(!isset($argv[$i+1])) {
                    $error = sprintf("Missing value for argument '%s'\n\n", $argv[$i]);
                    return null;
                }
                break;

            case 'help':
            case 'no-print-stats':
                break;

            default:
                $error = sprintf("The supplied argument '%s' is not a valid option\n\n", $argv[$i]);
                return null;
                break;
        }

        // Apply value
        switch($option) {
            case 'resolvers':
            case 'wordlist':
            case 'domain':
                $result[$option][] = $argv[$i+1];
                $i++;
                break;
            case 'timeout':
            case 'qps':
                $result[$option] = $argv[$i+1];
                $i++;
                break;
            case 't':
                if(!isset(DNS_TYPES_BY_NAME[strtoupper($argv[$i+1])])) {
                    $error = sprintf("Invalid value for argument '%s'\nValid values: %s\n\n", $argv[$i], implode('|', DNS_TYPES_BY_VALUE));
                    return null;
                }
                $result['types'][] = DNS_TYPES_BY_NAME[strtoupper($argv[$i+1])];
                $i++;
                break;
            case 'no-print-stats':
                $result['print_stats'] = false;
                break;
            case 'help':
                $error = '';
                return null;
                break;
        }
    }

    if(empty($result['types'])) {
        $result['types'] = array(1); // type A queries
    }

    foreach(array('wordlist', 'resolvers', 'domain', 'types') as $key) {
        if(empty($result[$key])) {
            $error = sprintf("Missing required argument: -%s\n\n", $key);
            return null;
        }
        $result[$key] = array_unique($result[$key]);
    }

    $result['timeout'] = floatval($result['timeout']);
    $result['qps'] = intval($result['qps']);

    return $result;
}

function print_usage(array $argv) : void
{
    fprintf(STDERR, 
		"Fast subdomain scanner 1.0 by OpenDataSecurity (https://opendatasecurity.io)\n" .
        "Usage: php %s (-wordlist ?)+ (-resolvers ?)+ (-domain ?)+ (-t ?)* [-timeout ?] [-qps ?] [-no-print-stats] [-help]\n" .
        "\n" .
        "Mandatory settings:\n" .
        "  -wordlist: Wordlist file to bruteforce subdomains\n" .
        "  -resolvers: File that contain DNS resolver IP addresses to allow parallel queries\n" .
        "  -domain: Base domain to generate subdomain names\n" .
        "\n" .
        "Optional settings:\n".
        "  -timeout: Timeout to wait for DNS replies before retrying query, in seconds (Default: 0.5)\n" .
        "  -qps: Maximum queries to do per second (Default: 2000)\n" .
        "  -t: DNS query types to do (Default: A)\n" .
        "  -no-print-stats: Do not print stats at the end (Default: print stats)\n" . 
        "  -help: Display this help only\n".
        "\n" .
        "The -wordlist, -resolvers, -domain and -t parameters may be repeated to allow multiple values.\n\n",
        $argv[0]
    );
}

// BEGIN

// Parse arguments
$error = '';
$options = parse_arguments($argv, $error);

if(!$options) {
    fputs(STDERR, $error);
    print_usage($argv);
    die();
}

// Read wordlist files
$wordlist = array();
foreach($options['wordlist'] as $wordlist_file) {
    $file = fopen($wordlist_file, 'r');
    if($file === false) {
        fprintf(STDERR, "Wordlist file '%s' could not be open for read\n", $wordlist_file);
        die();
    }
    while(($line = fgets($file)) !== false) {
        $line = trim($line);
        if(empty($line)) {
            continue;
        }
        $wordlist[] = $line;
    }
    fclose($file);
    unset($file);
}
unset($options['wordlist']);
unset($wordlist_file);

// Remove duplicates in wordlist
$wordlist = array_unique($wordlist);

if(empty($wordlist)) {
    fprintf(STDERR, "The specified wordlist files are empty or could not be read, aborting...\n");
    die();
}

// Generate all subdomain wordlist with domains and wordlist items
$wordlist_subdomains = array();
foreach($options['domain'] as $domain) {
    foreach($wordlist as $wordlist_item) {
        $wordlist_subdomains[] = "$wordlist_item.$domain";
    }
}
unset($options['domain']);
unset($wordlist_item);
unset($domain);
unset($wordlist);

// Remove duplicates in subdomain wordlist
$wordlist_subdomains = array_unique($wordlist_subdomains);

// Read resolver files
$resolver_wordlist = array();
foreach($options['resolvers'] as $resolvers_file) {
    $file = fopen($resolvers_file, 'r');
    if($file === false) {
        fprintf(STDERR, "Resolvers file '%s' could not be open for read\n", $wordlist_file);
        die();
    }
    while(($line = fgets($file)) !== false) {
        $line = trim($line);
        if(empty($line)) {
            continue;
        }
        $resolver_wordlist[] = $line;
    }
    fclose($file);
}
unset($options['resolvers']);
unset($file);
unset($line);
unset($resolvers_file);

// Remove duplicates in resolvers list
$resolver_wordlist = array_unique($resolver_wordlist);

if(empty($resolver_wordlist)) {
    fprintf(STDERR, "The specified resolvers list files are empty or could not be read, aborting...\n");
    die();
}

// Generate a UDP socket for each DNS resolver
$resolvers = array();
foreach($resolver_wordlist as $resolver_item) {
    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if($socket !== false) {
        socket_connect($socket, $resolver_item, 53);
        socket_set_nonblock($socket);
        $resolvers[$resolver_item] = $socket;
        unset($socket);
    }
}
unset($resolver_wordlist);

// Objects to store DNS queries and received responses
$query = new DnsQuery();
$response = new DnsMessage();

// Store total queries to be done
$total_query_count = count($wordlist_subdomains) * count($options['types']);

// Store pending queries list and current queries in waiting state
$current_queries = array();

if($options['print_stats']) {
    echo "starting...\n";
}
$found = 0;
$start_time = microtime(true);

// Helper counters
$queries_done = 0;
$last_update = 0;

// Repeat loop until ongoing query list and pending domain list are both empty
while(!empty($current_queries) || !empty($wordlist_subdomains)) {
    $read = $resolvers;
    $write = (count($wordlist_subdomains) || count($current_queries)) ? $read : null;
    $except = null;
    
    // Print statistics each 15 seconds
    if($options['print_stats'] && microtime(true) - $last_update > 15) {
        printf("%d queries ongoing, %d queries done, %d queries total, %d queries pending...\n",
            count($current_queries), $queries_done, $total_query_count,
            count($wordlist_subdomains) * count($options['types']));
        $last_update = microtime(true);
    }
    
    // Do select call
    if(socket_select($read, $write, $except, 0, 0) > 0) {

        // Check writable sockets, then send DNS queries
        if(count($write)) {
            $domain = null;

            // Get a random domain name from pending domain list, if there is pending domains
            if(count($wordlist_subdomains)) {
                $domain_key = array_keys($wordlist_subdomains)[rand(0, count($wordlist_subdomains)-1)];
                $domain = $wordlist_subdomains[$domain_key];
                $query_send_types = $options['types'];
                unset($wordlist_subdomains[$domain_key]);

            // If no pending domains, get a domain from queries that are still not replied and timed out according to configuration
            } else {
                $timeout_query = array_custom_search($current_queries, function($query) use ($options) { return microtime(true) - $query['timestamp'] > $options['timeout']; })->current();
                if($timeout_query) {
                    $domain = $timeout_query['domain'];
                    $query_send_types = array($timeout_query['type']);
                    unset($current_queries[$timeout_query['id']]);
                }
            }

            // There is a domain to be queries
            if($domain !== null) {
                // Send a query of each type for that domain
                foreach($query_send_types as $type) {
                    $query_id = md5($domain.'***'.$type);
                    if(!isset($current_queries[$query_id])) {
                        $query->newQuestion($type, $domain);
                        $current_queries[$query_id] = array('domain' => $domain, 'type' => $type, 'id' => $query->getId(), 'timestamp' => microtime(true), 'id' => $query_id, 'req_id' => $query->getId());
                        $query_bin = $query->serialize();
                        do {
                            $server = array_keys($write)[rand(0, count($write)-1)];
                            $socket = $write[$server];
                        } while(@socket_send($socket, $query_bin, strlen($query_bin), MSG_EOF) !== strlen($query_bin));
                        $queries_done++;
                        usleep((1/$options['qps'])*1000000);
                    }
                }
            }
        }

        // Check readable sockets, then read and print DNS replies
        if(count($read)) {
            $port = '53';
            foreach($read as $server => $socket) {
                @socket_recvfrom($socket, $result, 512, 0, $server, $port);
                if($result) {
                    // Parse response
                    $response->parse($result, 0);
                    $id = $response->getHeader()->getId();
                    $questions = $response->getQuestions();

                    // Check questions that should come with response
                    if(count($questions)) {

                        // Get domain name
                        $domain = implode('.', $questions[0]->getQname()->getParsed());

                        // Get question type
                        $type = $questions[0]->getQtype();

                        // Check if this reply is matched with a query in the query list
                        $matched_query = $current_queries[md5($domain.'***'.$type)] ?? null;

                        // Matched -> remove from list and print answers
                        if($matched_query) {
                            unset($current_queries[$matched_query['id']]);
                            foreach($response->getAnswers() as $answer) {
                                echo "$answer\n";
                                $found++;
                            }
                        }
                    }
                }
            }
        }
    }
}

// Calculate time taken and retried queries
if($options['print_stats']) {
    $time_taken = microtime(true)-$start_time;
    $retried_queries = $queries_done - $total_query_count;

    echo "\n\n";
    printf("%d subdomains found in %d queries, with %d retried queries. Time taken: %.2f seconds\n", $found, $queries_done, $retried_queries, $time_taken);
    printf("Total query rate: %.2f q/s, effective query rate: %.2f q/s\n\n", $queries_done/$time_taken, $total_query_count/$time_taken);
}
