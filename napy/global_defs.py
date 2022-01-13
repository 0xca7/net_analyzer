"""
    This file is there to synchronize the wireshark
    columns with the python script.

    Expected columns:
    "No.","Time","Source","Destination","Sport",
    "Dport","Protocol","Length","Smac","Dmac","Info"
"""

FIELD_SOURCE_IP = 'Source'
FIELD_DEST_IP   = 'Destination'

FIELD_INDEX_SIP     = 2
FIELD_INDEX_DIP     = 3
FIELD_INDEX_SPORT   = 4
FIELD_INDEX_DPORT   = 5
FIELD_INDEX_PROTO   = 6
FIELD_INDEX_LEN     = 7
FIELD_INDEX_SMAC    = 8
FIELD_INDEX_DMAC    = 9

"""
gotta have some ascii banners right?
"""

REPORT_TITLE = ("""
  _  _     _     _             _                 
 | \| |___| |_  /_\  _ _  __ _| |_  _ ______ _ _ 
 | .` / -_)  _|/ _ \| ' \/ _` | | || |_ / -_) '_|
 |_|\_\___|\__/_/ \_\_||_\__,_|_|\_, /__\___|_|  
                                 |__/           
 Analysis Report
 ------------------------------------------------
""")

BANNER = ("""
  _  _     _     _             _                 
 | \| |___| |_  /_\  _ _  __ _| |_  _ ______ _ _ 
 | .` / -_)  _|/ _ \| ' \/ _` | | || |_ / -_) '_|
 |_|\_\___|\__/_/ \_\_||_\__,_|_|\_, /__\___|_|  
                                 |__/           
""")



