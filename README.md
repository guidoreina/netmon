netmon
======
Network monitor for Linux.

## `netmon`
`netmon` processes IP packets coming either from a network interface or from a PCAP file and generates six kind of events:

* ICMP: containing the following information:
  * Timestamp
  * Source address
  * Destination address
  * Number of bytes transferred
  * ICMP type
  * ICMP code

* UDP: containing the following information:
  * Timestamp
  * Source address
  * Source port
  * Destination address
  * Destination port
  * Number of bytes transferred

* DNS (request and response): containing the following information:
  * Timestamp
  * Source address
  * Source port
  * Destination address
  * Destination port
  * Number of bytes transferred
  * Domain queried
  * For responses: list of IP addresses

* Begin TCP connection: containing the following information:
  * Timestamp
  * Source address
  * Source port
  * Destination address
  * Destination port

* TCP data: containing the following information:
  * Timestamp
  * Source address
  * Source port
  * Destination address
  * Destination port
  * Number of bytes of payload

* End TCP connection: containing the following information:
  * Timestamp
  * Source address
  * Source port
  * Destination address
  * Destination port
  * Creation timestamp
  * Number of bytes transferred by the client
  * Number of bytes transferred by the server

These events are written to a file in binary format, one file per worker thread.

## `evmerger`
The event files can be merged using `evmerger`, which takes two or more event files and generates an output file containing all the events.


## `evreader`
The event files can be viewed using `evreader`, which can dump the events in the following formats:

* Human readable
* JSON
* Javascript
* CSV

`evreader` has a DNS cache for IPv4 and a DNS cache for IPv6 and can provide (when possible) the source hostname and the destination hostname.


## `evconnections`
Takes as input an event file and generates as output an event file with the "End TCP connection" events. The events can be sorted by:

* Duration
* Transferred client
* Transferred server
* Transferred


## Usages:

###### `netmon`
```
./netmon OPTIONS

OPTIONS:
  Capture configuration:
    --capture-method <method>
      <method> ::= "pcap" | "ring-buffer" | "socket"
      Mandatory.

    --capture-device <device>
      <device>: either a PCAP filename for the capture method "pcap" or
                the name of a network interface.
      Mandatory.

    --rcvbuf-size <size>
      <size>: size of the socket receive buffer.
      Greater or equal than: 2048, default: not set.
      Optional.

    --promiscuous-mode
      Enable interface's promiscuous mode.
      Default: no.
      Optional.


  Ring buffer configuration:
    --ring-buffer-block-size <size>
      <size>: size of the ring buffer block.
      Range: 128 .. 18446744073709551615, default: 4096.
      Optional.

    --ring-buffer-frame-size <size>
      <size>: size of the ring buffer frame.
      Range: 128 .. 18446744073709551615, default: 2048.
      Optional.

    --ring-buffer-frame-count <number>
      <number>: number of frames in the ring buffer.
      Range: 8 .. 18446744073709551615, default: 512.
      Optional.


  TCP/IPv4 hash table configuration:
    --tcp-ipv4-hash-size <number>
      <number>: size of the hash table.
      Range: 256 .. 4294967296, default: 4096.
      Optional.

    --tcp-ipv4-max-connections <number>
      <number>: maximum number of connections.
      Range: 256 .. 4294967296, default: 1048576.
      Optional.

    --connection-timeout <number>
      <number>: connection timeout (seconds).
      Greater or equal than: 5, default: 7200.
      Optional.

    --tcp-time-wait <number>
      <number>: TCP time wait (seconds).
      Greater or equal than: 1, default: 120.
      Optional.


  TCP/IPv6 hash table configuration:
    --tcp-ipv6-hash-size <number>
      <number>: size of the hash table.
      Range: 256 .. 4294967296, default: 4096.
      Optional.

    --tcp-ipv6-max-connections <number>
      <number>: maximum number of connections.
      Range: 256 .. 4294967296, default: 1048576.
      Optional.

    --connection-timeout <number>
      <number>: connection timeout (seconds).
      Greater or equal than: 5, default: 7200.
      Optional.

    --tcp-time-wait <number>
      <number>: TCP time wait (seconds).
      Greater or equal than: 1, default: 120.
      Optional.


  Workers configuration:
    --number-workers <number>
      <number>: number of worker threads.
      Range: 1 .. 1024, default: 4.
      Optional.

    --processors "all" | "even" | "odd" | <processor-list>
      <processor-list> ::= <processor>[,<processor>]*
      <processor> ::= 0 .. 7
      Optional.

    --events-directory <directory>
      <directory>: directory where to save the event files.
      Default: ".".
      Optional.

    --file-allocation-size <size>
      <size>: file allocation size.
      Default: 1073741824.
      Optional.

    --event-writer-buffer-size <size>
      <size>: size of the event writer buffer.
      Greater or equal than: 1024, default: 32768.
      Optional.

<number> ::= <digit>+
<size> ::= <number>[KMG]
           Optional suffixes: K (KiB), M (MiB), G (GiB)

```


###### `evmerger`
```
Usage: ./evmerger <input-event-file> ... <input-event-file> <output-event-file>
```


###### `evreader`
```
Usage: ./evreader [OPTIONS] --input-filename <filename>

Options:
  --help
  --output-filename <filename>
    <filename>: Name of the file where to save the output.
    Default: standard output.
  --output <output>
    <output> ::= "header" | "human-readable" | "json" | "javascript" | "csv"
    Default: "human-readable"
  --format <format>
    <format> ::= "pretty-print" | "compact"
    Default: "pretty-print"
  --csv-separator <character>
    <character>: CSV character separator.
    Default: ','

```


###### `evconnections`
```
Usage: ./evconnections [OPTIONS] --input-filename <filename> --output-filename <filename>

Options:
  --help
  --compare <compare-function>
    <compare-function> ::= "duration" | "transferred-client" | "transferred-server" | "transferred"
  --order <sort-order>
    <sort-order> ::= "ascending" | "descending"
    Default: "ascending"
```


## `qevents`
Qt program which displays the TCP connections from a JSON file containing events.
