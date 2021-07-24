"""
reader and preproc for csv files
"""

from napy.global_defs import *
from napy.filter import filter_remove_ipv6
from typing import List
import pandas as pd

"""
class to read, filter and output values
from a csv dumped from wirshark
"""
class NetReader():

    def __init__(self,fname) -> None:
        print('[+] NetReader: reading data...')
        self.df = pd.read_csv(fname)
        self.df = self.df.fillna(0)
        print('[+] NetReader: done.')
        self.raw_data = self.df.values.tolist() 

    def head(self) -> None:
        print(self.df.head())

    def filter_v4(self):
        print('[+] NetReader: filtering IPv4')
        self.raw_data = filter_remove_ipv6(self.raw_data)
        print('[+] NetReader: done.')

    def get_raw(self) -> List:
        return self.raw_data

    def get_sips(self) -> List:
        return self.df[FIELD_SOURCE_IP].to_list()

    def get_dips(self) -> List:
        return self.df[FIELD_DEST_IP].to_list()

    
    

    




