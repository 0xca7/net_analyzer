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


use std::fmt;
use std::net::Ipv4Addr;

/// port type can either be TCP or UDP
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Protocol{
    ICMP,
    TCP,
    UDP,
    ARP,
    Unknown,
}

impl fmt::Display for Protocol {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let s = match self {
            Protocol::ICMP    => "ICMP",
            Protocol::TCP     => "TCP",
            Protocol::UDP     => "UDP",
            Protocol::ARP     => "ARP",
            Protocol::Unknown => "Unknown",
        };

        write!(f,"{}", s)
    }

}

/// strong type for ports
#[derive(PartialEq, Eq, Hash, Clone, Copy, Ord, PartialOrd)]
pub struct PortAddr(pub u16);

impl fmt::Display for PortAddr {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }

}

/// type to model a MAC address
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct MacAddr(u8,u8,u8,u8,u8,u8);

impl MacAddr {

    /// create a new MAC addr instance from 
    /// a byte slice `bytes` taken from a dump
    pub fn new(bytes: &[u8]) -> Self {
        MacAddr(bytes[0], bytes[1], bytes[2], 
            bytes[3], bytes[4], bytes[5])
    }

}

impl fmt::Display for MacAddr {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, 
            self.3, self.4, self.5)
    }

}



#[derive(Eq, PartialEq, Hash)]
pub struct PacketData {
    sip:    Ipv4Addr,
    dip:    Ipv4Addr,
    smac:   MacAddr,
    dmac:   MacAddr,
    sport:  PortAddr,
    dport:  PortAddr,
    proto:  Protocol,
}

impl PacketData {

    /// create a new packet info struct from a builder
    pub fn new() -> PacketDataBuilder {
        PacketDataBuilder::new()
    }

    /// get a string containing packet data in graph form
    pub fn write_graph(&self) -> String {
        if self.proto == Protocol::ARP {
            return format!("{},{}\n", self.smac, self.dmac)
        }
        format!("{:?},{:?}\n", self.sip, self.dip)
    }

    /// get a string containing packet data in dot language form
    pub fn write_dot(&self) -> String {
        if self.proto == Protocol::ARP {
            return format!("\"{}\" -> \"{}\"\n", self.smac, self.dmac)
        }
        format!("\"{:?}\" -> \"{:?}\"\n", self.sip, self.dip)
    }

    pub fn get_sip(&self) -> Ipv4Addr {
        self.sip
    }

    pub fn get_dip(&self) -> Ipv4Addr {
        self.dip
    }

    pub fn get_sport(&self) -> PortAddr {
        self.sport
    }

    pub fn get_dport(&self) -> PortAddr {
        self.dport
    }

    pub fn get_smac(&self) -> MacAddr {
        self.smac
    }

    pub fn get_dmac(&self) -> MacAddr {
        self.dmac
    }

}

impl fmt::Display for PacketData {

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let mut s = String::new();

        // either TCP or UDP
        if self.sport.0 != 0 {
            s = format!("{:?}:{} => {:?}:{} {}", 
                self.sip, self.sport.0,
                self.dip, self.dport.0,
                self.proto);
        } else {
            // this is ICMP, ARP or Unknown
            if self.proto == Protocol::ICMP {
                s = format!("{:?} => {:?} {}", 
                    self.sip,
                    self.dip,
                    self.proto);
            }
            if self.proto == Protocol::ARP {
                s = format!("{} => {} {}", 
                    self.smac,
                    self.dmac,
                    self.proto);
            }

        }

        write!(f, "{}", s)
    }

}

pub struct PacketDataBuilder {
    smac:   MacAddr,
    dmac:   MacAddr,
    proto:  Protocol,
    sip:    Option<Ipv4Addr>,
    dip:    Option<Ipv4Addr>,
    sport:  Option<PortAddr>,
    dport:  Option<PortAddr>,
}

impl PacketDataBuilder {

    /// new, generic PacketDataBuilder
    pub fn new() -> Self {
        PacketDataBuilder { 
            sip: None, dip: None, 
            smac: MacAddr(0,0,0,0,0,0), 
            dmac: MacAddr(0,0,0,0,0,0), 
            sport: None, dport: None, proto: Protocol::Unknown 
        }
    }

    /// add IP addresses 
    pub fn ips(&mut self, sip: Ipv4Addr, dip: Ipv4Addr) -> &mut Self {
        self.sip = Some(sip);
        self.dip = Some(dip);
        self
    }

    /// add ports
    pub fn ports(&mut self, sport: PortAddr, dport: PortAddr) -> &mut Self {
        self.sport = Some(sport);
        self.dport = Some(dport);
        self
    }

    /// set the protocol
    pub fn protocol(&mut self, proto: Protocol) -> &mut Self {
        self.proto = proto;
        self
    }

    /// set mac addrs 
    pub fn macs(&mut self, smac: MacAddr, dmac: MacAddr) -> &mut Self {
        self.smac = smac;
        self.dmac = dmac;
        self
    }

    /// builder
    pub fn build(&mut self) -> PacketData {
        PacketData {
            smac: self.smac,
            dmac: self.dmac,
            sip: self.sip.unwrap_or(Ipv4Addr::new(0,0,0,0)),
            dip: self.dip.unwrap_or(Ipv4Addr::new(0,0,0,0)),
            proto: self.proto,
            sport: self.sport.unwrap_or(PortAddr(0)),
            dport: self.dport.unwrap_or(PortAddr(0)),
        }
    }
    

}
