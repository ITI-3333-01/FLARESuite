# FLARESuite
A collection of services used for packet research and analysis.

* **Core**: core code shared by all other parts of the suite, contains useful utilities and APIs that each service needs in order to run and work in unison.
* **Collector**: runs on the collection node and sends packet data collected from the desired NIC over the network to the aggregation node
  * Options:
    * `--interface` - Interface to collect from
    * `--choose-interface` - Pick an interface to collect from instead of choosing
    * `--buffer-size` - The PCAP buffer size to use
    * `--filter` - The PCAP filter to use
    * `--stats-window` - Time (in seconds) before a new stats dump is created
    * `--redis-host` - Hostname of the redis server used for cross-node communication
    * `--redis-port` - Port of the redis server used for cross-node communication
* **Aggregator**: runs on the aggregation node and handles incoming data from collector nodes
  * Options:
    * `--out` - The file to  print collected data to 
    * `--redis-host` - Hostname of the redis server used for cross-node communication
    * `--redis-port` - Port of the redis server used for cross-node communication
* **Daemon**: Runs on any managed nodes without direct shell access. Receives commands to perform predefined actions (restart, get CPU usage, etc).
