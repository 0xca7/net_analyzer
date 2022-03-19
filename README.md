# Net Analyzer

## Summary

This application takes a pcap file and creates a short summary of it. I use this in my work when I obtain some network data in order to get a brief overview of the pcap I'm looking at.

Because I thought this might be of use to others, I decided to open source the project, although it's not very sophisticated it may save some time.

This was in Python3 before, I rewrote this is Rust, because it's faster and more usable. The plotting is still done via Python3's **pyvis, networkx, scipy, pandas and matplotlib**.

Conversion of the supplied pcap file to csv is done using **tshark**.

## Usage

I will demonstrate usage via a test pcap file I supply with this repo.

```
# bootstrap (just creates the results directory at this time)
./bootstrap.sh

# run the application
cargo run -- captures/test.pcap report

# report is the name of the "report", a timestamp will be added.
# netanalyzer is applied to test.pcap.csv, which will be written
# to the "captures folder"

tree results/

results/
├── graph.csv
├── graph.png
└── report-13_2_2022-20_26_12.txt

0 directories, 3 files

# your browser will open and display an animated graph
# the graph is also saved in "nx.html"
```

That's it, you now have a report in results and a graph of the network. The graph saved to results/graph.png can get very messy of there are a lot of hosts, so play with py/visualize.py, use the interactive graph or just forget about the graph altogether :^) :-P

### 0xca7
