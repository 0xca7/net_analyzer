/*
    net-analyze - quick summary of pcap dumps
    Copyright (C) 2022  0xca7

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::thread;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use pcap::{Capture, Offline};

use crate::util;
use crate::pinfo::{PacketData, MacAddr, PortAddr, Protocol};

/// ethertype field for IPv4
const ETHERTYPE_IPV4: u16 = 0x0800;

/// ethertype field for ARP
const ETHERTYPE_ARP:  u16 = 0x0806;

/// ethertype field for IPv6
const ETHERTYPE_IPV6:  u16 = 0x86DD;

/// open a capture
pub fn open_capture(fpath: &str) -> Capture<Offline> {

    let cap = Capture::from_file(fpath);

    let capture = match cap {
        Ok(capture) => capture,
        Err(e) => {
            eprint!("error: {}\n", e);
            std::process::exit(1);
        },
    };

    capture
}


/// parse the capture
pub fn parse(cap: &mut Capture<Offline>) -> HashSet<PacketData> {

    let mut packets = HashSet::new();

    let state = Arc::new(Mutex::new((true, 0u64)));

    // this makes everything slow... :/
    let handle = {
        // scope off the cloned state
        let state = Arc::clone(&state);
        // spawn off progress bar here.
        thread::spawn( move || {
            util::progressbar(state);
        })
    };

    // iterate through all packets
    while let Ok(packet) = cap.next_packet() {

        // total packets seen
        let mut state = state.lock().unwrap();
        state.1 += 1;

        // we want to skip certain packets, for example IPv6
        let mut ignore = false;

        let mut pdata = PacketData::new();

        // get the mac addresses
        let dmac = MacAddr::new(packet.get(0..6)
            .unwrap());
        let smac = MacAddr::new(packet.get(6..12)
            .unwrap());

        pdata.macs(smac, dmac);

        let bytes = packet.get(12..14)
            .unwrap();

        // check the ethertype
        let ethertype = (bytes[0] as u16) << 8 | (bytes[1] as u16);

        if ethertype == ETHERTYPE_IPV4 {

            let ipv4 = packet.get(14..).unwrap();

            // get the internet header length
            let ihl = ipv4[0] & 0x0f;

            // get ips
            let sip = Ipv4Addr::from(
                parse_to_u32(&ipv4[12..16]));
            let dip = Ipv4Addr::from(
                parse_to_u32(&ipv4[16..20]));
            
            pdata.ips(sip, dip);

            // get the protocol
            let proto = &ipv4[9];

            let proto = match *proto {
                1  => Protocol::ICMP,
                6  => Protocol::TCP,
                17 => Protocol::UDP,
                _  => Protocol::Unknown,
            };

            // add the protocol
            pdata.protocol(proto);

            if proto == Protocol::TCP || proto == Protocol::UDP {


                // get next data
                let offset = (ihl * 4) as usize;

                let sport = u16::from_be_bytes(
                    parse_to_u16(&ipv4[offset..offset+2]));
                let dport = u16::from_be_bytes(
                    parse_to_u16(&ipv4[offset+2..offset+4]));

                let sport = PortAddr { 0: sport};
                let dport = PortAddr { 0: dport};

                // add ports
                pdata.ports(sport, dport);

            } 
        } else {
            // it's not IPv4
            match ethertype {
                ETHERTYPE_ARP  => {
                    // we might want to do some additional work here,
                    // for instance log the number of ARP packets, replies etc.
                    pdata.protocol(Protocol::ARP);
                },
                ETHERTYPE_IPV6 => ignore = true,
                _                   => {
                    // we might want to do additional work here as well,
                    // for instance log the unknown protocol
                    pdata.protocol(Protocol::Unknown);
                    ignore = true;
                },
            }
        }

        if !ignore {
            packets.insert(pdata.build());
        }

    }

    let mut state = state.lock().unwrap();
    let total = state.1;
    state.0 = false;
    drop(state);

    handle.join().unwrap();

    print!("----------------------------------\n");
    print!("[+] done! {} packets parsed\n", total);
    packets
}

/// get a u32 from a buffer
fn parse_to_u32(buffer: &[u8]) -> [u8;4] {
    buffer.try_into().expect("incorrect length")
}

/// get a u16 from a buffer
fn parse_to_u16(buffer: &[u8]) -> [u8;2] {
    buffer.try_into().expect("incorrect length")
}
