# Net Analyzer

## Summary

This application takes a pcap file and creates a short summary of it.
I use this in my work when I obtain some network data in order to get
a brief overview of the pcap I'm looking at.

Because I thought this might be of use to others, I decided to open
source the project, although it's not very sophisticated it may save
some time.

This was in Python3 before, I rewrote this is Rust, because it's faster and more usable. The plotting is still done via Python3's **networkx, pandas and matplotlib**

## Usage

I will demonstrate usage via a test pcap file I supply with this repo.

```
# bootstrap (just creates the results directory at this time)
./bootstrap.sh

# convert the pcap to csv, yields captures/test.pcap.csv
./captures/conv_csv.sh captures/test.pcap

# run the application
cargo run -- captures/test.pcap.csv report

[+] read 141 packets from csv
[+] reading CSV took 1.470697ms
[+] analysis took 102.449µs
[+] report will be written as: results/report-13_2_2022-20_26_12.txt
[+] writing graph
[+] done!

# report is the name of the report, a timestamp will be added
# netanalyzer is applied to test.pcap.csv

tree result/

results/
├── graph.csv
├── graph.png
└── report-13_2_2022-20_26_12.txt

0 directories, 3 files
```

That's it, you now have a report in results and a graph of the network.
The graph can get very messy of there are a lot of hosts, so play with
py/visualize.py or just forget about the graph :^)

### 0xca7
