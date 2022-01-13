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

"""Return true if the file exists

checks if a file exists or not
"""
def check_file(filename):
    check = Path(filename)
    return check.is_file()

"""Return 1 if exception occured

the main function of the network analyzer
"""
def main():

    print(BANNER)

    try:
        os.mkdir(OUTPATH)
    except OSError as e:
        # if directory already exists, we don't care
        if e.errno != 17: 
            print('output directory:\n{}\n'.format(e))
            sys.exit(1)
    else:
        print('output will be written to: {}'.format(OUTPATH))
        

    # check argument number
    if len(sys.argv) <= 1:
        print('usage: ./net_analyze [csv-file]')
        sys.exit(1)

    # check if the file to analyze exists
    filename = sys.argv[1]

    if not check_file(filename):
        print('[!] no such file: {}'.format(filename))
        sys.exit(1)

    # get the start time in order to calculate the 
    # total time spent for analysis later
    start = time.time()

    # read the data from a csv file passed as an arg
    reader = NetReader(filename)

    # filter so only IPv4 packets remain
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

    # draw edges between IPs by using connections 
    vis.add_edges(con)

    # mark the end of the analysis output
    print('-------------------------------------')

    # plot the graph, save plot to a file
    print('[+] writing connection graph')
    vis.show(OUTPATH)

    # write out the report 
    print('[+] writing report')
    write_report(filename, OUTPATH, analyzer, con_ip, con)

    # show the total time spent for analysis and reporting
    print('[+] time taken: {}'.format(time.time() - start))
    

if __name__ == '__main__':
    main()

