import numpy as np
from napy.global_defs import *

"""
main class to extract information from a 
wireshark csv dump
"""
class NetAnalyzer():

    """
    initializes a new NetAnalyzer instance 
    with data read from a csv
    """
    def __init__(self, data) -> None:
        self.data = data

    """
    raw printing of the data, can be used for debugging
    """
    def show(self) -> None:
        print(self.data)

    """int
    get the total number of packets in the csv file
    """
    def get_no_packets(self) -> int:
        return len(self.data)
    
    """list
    get a list of de-duped IP addresses in the csv
    """
    def get_ips(self) -> list:
        unique_sips = set( [x[FIELD_INDEX_SIP] for x in self.data] ) 
        unique_dips = set( [x[FIELD_INDEX_DIP] for x in self.data] )
        return list(unique_sips.union(unique_dips))
    
    """list
    get all the IP addresses in the `source ip` column
    """
    def get_raw_sips(self) -> list:
        return [ x[FIELD_INDEX_SIP] for x in self.data ]

    """list
    get all the IP addresses in the `destination ip` column
    """
    def get_raw_dips(self) -> list:
        return [ x[FIELD_INDEX_DIP] for x in self.data ]

    """list
    get all the ports in the `sports` column
    """
    def get_sports(self) -> list:
        return [int(x[FIELD_INDEX_SPORT]) for x in self.data]

    """list
    get all the ports in the `dports` column
    """
    def get_dports(self) -> list:
        return [int(x[FIELD_INDEX_DPORT]) for x in self.data]

    """list
    get a list of all the unique ports in the csv
    """
    def get_ports(self) -> list:
        unique_sports = set( filter(lambda x: x != 0,   
            [int(x[FIELD_INDEX_SPORT]) for x in self.data]) ) 
        unique_dports = set( filter(lambda x: x != 0, 
            [int(x[FIELD_INDEX_DPORT]) for x in self.data]) )
        return list(unique_sports.union(unique_dports))

    """list
    get only the well known ports, below 1024
    """
    def get_well_known_ports(self) -> list:
        unique_sports = set( filter(lambda x: x < 1024 and x != 0, 
            [int(x[FIELD_INDEX_SPORT]) for x in self.data]) )
        unique_dports = set( filter(lambda x: x < 1024 and x != 0, 
            [int(x[FIELD_INDEX_DPORT]) for x in self.data]) )
        return list(unique_sports.union(unique_dports))

    """list
    get all unique MAC addresses found in the csv
    """
    def get_macs(self) -> list:
        unique_smacs = set( [x[FIELD_INDEX_SMAC] for x in self.data] ) 
        unique_dmacs = set( [x[FIELD_INDEX_DMAC] for x in self.data] )
        return list(unique_smacs.union(unique_dmacs))

    """list
    get all protocols found in the csv
    """
    def get_protos(self) -> list:
        unique_protos = set( [x[FIELD_INDEX_PROTO] for x in self.data] ) 
        return list(unique_protos)

    """int
    get the maximum packet length found in the csv
    """
    def get_max_len(self) -> int:
        unique_lens = set( [ int(x[FIELD_INDEX_LEN]) for x in self.data] )
        return np.max(list(unique_lens))

    """int
    get the minimum packet length found in the csv
    """
    def get_min_len(self) -> int:
        unique_lens = set( [ int(x[FIELD_INDEX_LEN]) for x in self.data] )
        return np.min(list(unique_lens))

    """
    get all ip connections, no ports
    this gives you a quick overview who is talking to who
    in a network 
    """
    def ip_connections(self) -> list:
        sips = self.get_raw_sips()
        dips = self.get_raw_dips()
        connections =  [ [x,y] for x,y in zip(sips, dips)]
        unique_connections = set()
        for con in connections:
            if (    (con[1],con[0]) not in unique_connections 
                    and (con[0],con[1]) not in unique_connections ):
                unique_connections.add((con[0],con[1]))
        return list(unique_connections)

    """
    more detailed connection information: who is talking to who
    using which port(s)
    """
    def connections(self) -> list:
        sips = self.get_raw_sips()
        dips = self.get_raw_dips()
        sports = self.get_sports()
        dports = self.get_dports()
        connections =  [ [sip, dip, sport, dport] 
            for sip, dip, sport, dport in zip(sips, dips, sports, dports)]
        unique_connections = set()
        for con in connections:
            if con[2] == 0:
                con[2] = '-'
                con[3] = '-'
            unique_connections.add((con[0], con[1], con[2], con[3]))
        return list(unique_connections)





 






        
