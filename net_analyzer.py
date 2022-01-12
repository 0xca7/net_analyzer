"""
    Reads a CSV exported from wireshark
    in the format specified in global_defs.
    Then proceeds to analyze the csv attempting
    to extract useful information from it.
    -- 0xca7
"""

import os
import sys
import time
from pathlib import Path

from napy.visualize import Visualizer
from napy.analyzer import NetAnalyzer
from napy.reader import NetReader
from napy.writer import write_report

from napy.global_defs import BANNER

OUTPATH = './output'

def check_file(filename):
    check = Path(filename)
    return check.is_file()

def main():

    print(BANNER)

    try:
        os.mkdir(OUTPATH)
    except OSError as e:
        # if directory already exists, we don't care
        if e.errno != 17: 
            print('output directory:\n{}\n'.format(e))
    else:
        print('output will be written to: {}'.format(OUTPATH))
        

    """
    check arguments
    """
    if len(sys.argv) <= 1:
        print('usage: ./net_analyze [csv-file]')
        sys.exit(1)

    filename = sys.argv[1]

    if not check_file(filename):
        print('[!] no such file: {}'.format(filename))
        sys.exit(1)

    """
    read data, analyze, write report 
    """
    start = time.time()

    # read the data from a csv file
    reader = NetReader(filename)
    # filter so only IPv4 remains
    reader.filter_v4()
    # get the filtered, raw, extracted data 
    data = reader.get_raw()

    # analyze the data which was read
    analyzer = NetAnalyzer(data)

    # get all IP connections only
    # shows who is talking to who
    con_ip = analyzer.ip_connections()

    # get IP connections with the respective ports
    # shows who is talking to who, by which ports / protocol
    con = analyzer.connections()

    # create a visualizer to show the connection graph
    vis = Visualizer()
    # get all ip addresses from the PCAP
    vis.add_nodes(analyzer.get_ips())
    # draw edges between them by using connections 
    vis.add_edges(con)

    # mark the end of the analysis output
    print('-------------------------------------')


    # plot the graph
    print('[+] writing connection graph')
    vis.show(OUTPATH)

    print('[+] writing report')
    write_report(filename, OUTPATH, analyzer, con_ip, con)

    print('[+] time taken: {}'.format(time.time() - start))
    

if __name__ == '__main__':
    main()

