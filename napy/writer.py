"""
    writes a report, summarizing the data
    analyzed in the PCAP
"""

from napy.global_defs import REPORT_TITLE

"""
write a single data item to a file
for example no. of packets in csv
"""
def write_single(out, title, data):
    out.write(title)
    out.write(data)
    out.write('\n')

"""
write multiple data items to a file
for example observed IP addresses
"""
def write_multiple(out, title, data, linebreak):
    line = 0
    out.write(title)
    for item in data:
        out.write(str(item) + '\t')
        if line == linebreak:
            out.write('\n')
            line = 0
        line += 1
    
    if len(data) <= linebreak:
        out.write('\n')
    out.write('\n')

"""
main report writer function
@param csv the csv filename
@param path the path to write to
@param analyzer NetAnalyzer class holding data
@param ip_con ip connections, no ports
@param con ip connections with ports
"""
def write_report(csv, path, analyzer, ip_con, con):

    csv = csv.split('/')
    filename = path + '/' + 'report_' + csv[-1] + '.txt'

    with open(filename, 'w') as out:
        out.write(REPORT_TITLE + '\n')

        write_single(out, '[+] no. packets analyzed: ',
            str(analyzer.get_no_packets()) + '\n')

        write_multiple(out, '[+] unique IP addresses:\n',
            analyzer.get_ips(), 5)

        write_multiple(out, '[+] unique ports:\n',
            analyzer.get_ports(), 10)

        write_multiple(out, '[+] well-known ports\n',
            analyzer.get_well_known_ports(), 10)

        write_multiple(out, '[+] unique MAC addresses:\n',
            analyzer.get_macs(), 5)

        write_multiple(out, '[+] protocols:\n',
            analyzer.get_protos(), 10)

        write_single(out, '[+] max. packet length: ',
            str(analyzer.get_max_len()))

        write_single(out, '[+] min. packet length:',
            str(analyzer.get_min_len()))

        out.write('\n[+] ip connections: \n')
        for c in ip_con:
            out.write(str(c) + '\n')

        out.write('\n[+] full connection overview: \n')
        for c in con:
            s = f'{c[0]}\t{c[2]}\t->\t{c[1]}\t{c[3]}'
            out.write(s + '\n')


        out.write('\n------------------------------------------------\n')

