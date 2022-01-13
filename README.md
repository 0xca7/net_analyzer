# NetAnalyzer
## summarizes network data captured with wireshark
### 0xca7


## Intro
This is my python script to summarize network data captured with wireshark.

## Usage
You need to have the following setup for your columns in wireshark, after you have that, export the PCAP as a csv:
```
"No.","Time","Source","Destination","Sport","Dport","Protocol","Length","Smac","Dmac","Info"
```

If you want to change any of this, my definitions are in `napy/global_defs.py`

If you have this set up, just run: 

```
python3 net_analyzer.py [csv filename]
```

NetAnalyzer will generate a report called `report_[csv filename].csv.txt` and a connection graph which will contain a summary of the csv. The output is written to the `output` directory.

## Sample Output

I included a sample capture in `sample_data` you may want to look at. It also contains the CSV file
that I analyze below.

```console
λ net_analyzer.py sample_data/sample_capture.csv 

  _  _     _     _             _                 
 | \| |___| |_  /_\  _ _  __ _| |_  _ ______ _ _ 
 | .` / -_)  _|/ _ \| ' \/ _` | | || |_ / -_) '_|
 |_|\_\___|\__/_/ \_\_||_\__,_|_|\_, /__\___|_|  
                                 |__/           

[+] NetReader: reading data...
[+] NetReader: done.
[+] NetReader: filtering IPv4
[+] NetReader: done.
[+] writing report
[+] time taken: 0.021047592163085938

λ cat report_sample_capture.csv.txt 

  _  _     _     _             _                 
 | \| |___| |_  /_\  _ _  __ _| |_  _ ______ _ _ 
 | .` / -_)  _|/ _ \| ' \/ _` | | || |_ / -_) '_|
 |_|\_\___|\__/_/ \_\_||_\__,_|_|\_, /__\___|_|  
                                 |__/           
 Analysis Report
 ------------------------------------------------

[+] no. packets analyzed: 19

[+] unique IP addresses:
127.0.0.1

[+] unique ports:
7777    1234    50868   42092

[+] well-known ports


[+] unique MAC addresses:
00:00:00_00:00:00

[+] protocols:
UDP     ICMP    TCP

[+] max. packet length: 98
[+] min. packet length:51

[+] ip connections: 
('127.0.0.1', '127.0.0.1')

[+] full connection overview: 
127.0.0.1       -       ->      127.0.0.1       -
127.0.0.1       50868   ->      127.0.0.1       1234
127.0.0.1       1234    ->      127.0.0.1       50868
127.0.0.1       42092   ->      127.0.0.1       7777

------------------------------------------------

```

## Summary Output

The report which is generated contains:

- Number of Packets
- IPs
- Ports
- Well-Known Ports
- Protocols found in the dump.
- Connections, only which IPs are communicating
- Connections, with IPs and Port Numbers

You also get a nice connection graph showing which IPs are communicating
with each other.

**any field which is not recognized or empty is replaced with zero**

### 0xca7
