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

/// this module is responsible for creating 
/// a report from a dump analysis

use crate::{DumpAnalysis, analyze::PortType};

use std::fs::OpenOptions;
use std::io::prelude::*;

const HEADER_SUM    : &'static str = "-- SUMMARY --\n";
const HEADER_COM    : &'static str = "-- Communications --\n";
const HEADER_PORTS  : &'static str = "-- Ports --\n";
const HEADER_PROTOS : &'static str = "-- Protocols --\n";

/// format the summary 
fn format_summary(no_unique: usize, no_coms: usize, no_ports: usize, no_protos: usize) -> String {

    let mut out = String::new();

    out.push_str(HEADER_SUM);

    let s = format!("-- unique packets: {}\n", no_unique);
    out.push_str(&s);

    let s = format!("-- number of communications: {}\n", no_coms);
    out.push_str(&s);

    let s = format!("-- number of ports: {}\n", no_ports);
    out.push_str(&s);

    let s = format!("-- number of protocols: {}\n", no_protos);
    out.push_str(&s);

    out

}

/// format the communications seen into a string
fn format_communications(com: Vec<(String, String, String)>) -> String {

    let mut out = String::new();

    out.push_str(HEADER_COM);

    for item in com {
        let s = format!("{} -> {} : {}\n", item.0, item.1, item.2);
        out.push_str(&s);
    }

    out

}

/// format the ports into a string
fn format_ports(ports: Vec<(PortType, u16)>) -> String {

    let mut out = String::new();

    out.push_str(HEADER_PORTS);

    for item in ports {
        let port_type = match item.0 {
            PortType::PortTcp => "TCP",
            PortType::PortUdp => "UDP",
        };

        let s = format!("{} ({})\n", item.1, port_type);
        out.push_str(&s);
    }

    out
}

/// format the protocol names 
fn format_protonames(names: Vec<String>) -> String {

    let mut out = String::new();

    out.push_str(HEADER_PROTOS);

    for item in names {
        let s = format!("{}\n", item);
        out.push_str(&s);
    }

    out

}

/// takes the dump analysis and writes a report from it
pub fn write_report(data: &DumpAnalysis, path: &String) {

    let no_unique = data.len();
    let connections = data.get_connections();
    let portnumbers = data.get_ports();
    let protocols = data.get_protocol_names();

    let sum    = format_summary(no_unique, connections.len(),
        portnumbers.len(), protocols.len());

    let coms   = format_communications(connections);
    let ports  = format_ports(portnumbers);
    let protos = format_protonames(protocols);


    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(path);

    // check this in main, before anything is called
    // we don't want a full analysis to run and tell us
    // we can't save it after x hours.
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            print!("can't create report file: {}", e);
            std::process::exit(1);
        },
    };

    if let Err(e) = writeln!(file, "{}", sum) {
        eprintln!("Couldn't write to file: {}", e);
    }

    if let Err(e) = writeln!(file, "{}", coms) {
        eprintln!("Couldn't write to file: {}", e);
    }

    if let Err(e) = writeln!(file, "{}", ports) {
        eprintln!("Couldn't write to file: {}", e);
    }

    if let Err(e) = writeln!(file, "{}", protos) {
        eprintln!("Couldn't write to file: {}", e);
    }

}

pub fn write_graph(data: &DumpAnalysis) {

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open("results/graph.csv");


    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            print!("write_graph error: {}\n", e);
            std::process::exit(1);
        },
    };

    // content begins with header
    let mut content = "src,dst\n".to_string();

    // get all edges and write them to a file
    // in csv format
    for connection in &data.connections {
        content.push_str(&format!("{},{}\n", 
            connection.0, connection.1));
    }

    if let Err(e) = writeln!(file, "{}", content) {
        eprintln!("Couldn't write to file: {}", e);
    }

}