
use std::hash::Hash;
use std::collections::HashSet;
use serde::Deserialize;



#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum PortType {
    PortTcp,
    PortUdp,
}

#[derive(Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct DataItem {
    #[serde(rename = "eth.src")]
    smac: String,
    #[serde(rename = "eth.dst")]
    dmac: String,
    #[serde(rename = "ip.src")]
    sip:  String,
    #[serde(rename = "ip.dst")]
    dip:  String,
    #[serde(rename = "ip.proto")]
    proto: String,
    #[serde(rename = "tcp.srcport")]
    sport: Option<String>,
    #[serde(rename = "tcp.dstport")]
    dport: Option<String>,
    #[serde(rename = "tcp.srcport")]
    usport: Option<String>,
    #[serde(rename = "tcp.dstport")]
    udport: Option<String>,
    #[serde(rename = "_ws.col.Protocol")]
    protostring: Option<String>,
}

impl DataItem {

    pub fn get_srcip(&self) -> String {
        self.sip.clone()
    }

    pub fn get_dstip(&self) -> String {
        self.dip.clone()
    }

    pub fn get_proto_string(&self) -> Option<String> {
        self.protostring.clone()
    }

}

/// contains unique packets and analysis results
pub struct DumpAnalysis {
    /// stores the unique packets found in the dump
    unique_packets: HashSet<DataItem>,
    /// stores all connections src IP -> dst IP
    pub connections: Vec<(String, String, String)>,
    /// stores all protocols found by name
    proto_names: Vec<String>,
    /// stores all unique ports
    ports: Vec<(PortType, u16)>,
}

impl DumpAnalysis {

    /// get a new DumpAnalysis instance
    pub fn new() -> DumpAnalysis {
        DumpAnalysis {
            unique_packets:     HashSet::new(),
            connections:        Vec::new(),
            proto_names:        Vec::new(),
            ports:              Vec::new(),
        }
    }

    /// len is always the largest item, which is the number
    /// of unique packets stored in this struct
    pub fn len(&self) -> usize {
        self.unique_packets.len()
    }

    /// insert a packet into the analysis only if it is unique
    pub fn insert_packet(&mut self, packet: DataItem) {
        self.unique_packets.insert(packet);
    }

    /// analyze the unique packets stored inside this struct
    pub fn analyze(&mut self) {
        self.analyze_connections_full();
    }

    /// analyzes all connections with IP:Port or
    /// MAC addresses, also includes the protocol name
    fn analyze_connections_full(&mut self) {

        let mut connections = HashSet::new();
        let mut ports = HashSet::new();
        let mut proto_names =  HashSet::new();

        for item in &self.unique_packets {

            let mut proto = String::new();

            // set to layer 2 packet by default
            let mut src = format!("{}", item.smac);
            let mut dst = format!("{}", item.dmac);

            // check if there is an IP, if yes, overwrite src/dst
            let sip = item.get_srcip();
            let dip = item.get_dstip();

            if sip != "" && dip != "" {

                // UDP
                if item.usport.is_some() {
                    src = format!("{}:{}", sip, item.usport.as_ref().unwrap());
                    dst = format!("{}:{}", dip, item.udport.as_ref().unwrap());

                    let port = get_port(&item.usport.as_ref().unwrap(), 
                        &item.udport.as_ref().unwrap());
                    ports.insert((PortType::PortUdp, port));
                }
                // TCP
                else if item.sport.is_some() {
                    src = format!("{}:{}", sip, item.sport.as_ref().unwrap());
                    dst = format!("{}:{}", dip, item.dport.as_ref().unwrap());

                    let port = get_port(&item.sport.as_ref().unwrap(), 
                    &item.dport.as_ref().unwrap());
                    ports.insert((PortType::PortTcp, port));
                } else {
                    // all others
                    src = format!("{}", item.sip); 
                    dst = format!("{}", item.dip);
                }

            } // if there is an IP

            // some protocols might lack a name
            if item.protostring.is_some() {
                proto = item.get_proto_string().unwrap();
                proto_names.insert(proto.clone());
            }

            // deduplicate
            connections.insert((src, dst, proto));
        }

        // convert to vector
        self.connections = connections.into_iter().collect();
        self.proto_names = proto_names.into_iter().collect();
        self.ports = ports.into_iter().collect();
    }

}

/// getter implementation
impl DumpAnalysis {

    /// getter for connections
    pub fn get_connections(&self) -> Vec<(String, String, String)> {
        self.connections.clone()
    }

    /// getter for protocol names
    pub fn get_protocol_names(&self) -> Vec<String> {
        self.proto_names.clone()
    }

    /// getter for ports
    pub fn get_ports(&self) -> Vec<(PortType, u16)> {
        self.ports.clone()
    }

}

fn get_port(sport: &String, dport: &String) -> u16 {

    // parse to u16
    let sport = sport.parse::<u16>().expect("error parse sport");
    let dport = dport.parse::<u16>().expect("error parse dport");

    // get the smaller port
    std::cmp::min(sport, dport)
}

