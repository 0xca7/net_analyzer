"""
    Reads a CSV exported from wireshark
    in the format specified in global_defs.
    Then proceeds to analyze the csv attempting
    to extract useful information from it.
    -- 0xca7
"""

import sys
import time
from pathlib import Path

from napy.analyzer import NetAnalyzer
from napy.reader import NetReader
from napy.writer import write_report

from napy.global_defs import BANNER


def check_file(filename):
    check = Path(filename)
    return check.is_file()

def main():

    print(BANNER)

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

    print('[+] writing report')
    write_report(filename, analyzer, con_ip, con)

    print('[+] time taken: {}'.format(time.time() - start))
    

if __name__ == '__main__':
    main()

