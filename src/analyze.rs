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

use std::fs;
use std::io::Error;
use std::io::prelude::*;
use std::collections::HashSet;

use crate::pinfo::{PacketData};

/*
    NOTES:
        - currently, a deduplication takes place for dotfiles and 
          the csv file for the graph. this might be removed if port
          numbers and/or protocols are added in future releases.
          for now, the deduplication remains in place because we are
          only looking at source/destination IP/MAC addrs.
*/

/// write the result as a dotfile
pub fn dotfile(pv: &Vec<PacketData>) -> Result<(), Error> {

    let mut connections = HashSet::new();

    let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open("out.dot")
                .unwrap();

    // TODO: if a node shall have a weight, it may be necessary to
    //       add duplicates here, so the de-duplication may not even
    //       be necessary.
    for item in pv {
        connections.insert(item.write_dot());
    }

    write!(file, "digraph g {{\n")?;
    for item in connections {
        write!(file, "{}", item)?;
    }
    write!(file, "}}")?;

    Ok(())
}

/// just executes the python program to visualize
/// for now, might be re-done in rust later
pub fn visualize(pv: &Vec<PacketData>) -> Result<(), Error> {

    let mut connections = HashSet::new();

    let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open("graph.csv")
                .unwrap();

    for item in pv {
        connections.insert(item.write_graph());
    }

    // NOTE: this is de-duplicated, because the CSV doesn't gain anything
    //       by having duplicates, of course, it may be that we actually 
    //       want a weight here, so I will leave this open for now.
    write!(file, "src,dst\n")?;
    for item in connections {
        write!(file, "{}", item)?;
    }

    let output = std::process::Command::new("python3")
        .arg("py/visualize.py")
        .output()
        .expect("failed to execute python visualizer");
        if !output.status.success() {
            print!("[+] error visualization\n");
            std::process::exit(1);
        }

    Ok(())
}

/// generate a report as a textfile 
pub fn generate_report(pv: &Vec<PacketData>) -> Result<(), Error> {

    let mut linebreak: usize =  1;
    let mut ips = HashSet::new();
    let mut ports = HashSet::new();
    let mut macs = HashSet::new();

    // get the unique ip addresses communicating 
    for item in pv {
        ips.insert(item.get_sip());
        ips.insert(item.get_dip());
        ports.insert(item.get_sport());
        ports.insert(item.get_dport());
        macs.insert(item.get_smac());
        macs.insert(item.get_dmac());
    }

    let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open("report.txt")
                .unwrap();

    write!(file, "-- Unique IP Adresses\n")?;
    for item in ips {

        // nicely format the strings in the report 
        let mut item = item.to_string();
        for _ in 0..15-item.len() {
            item.push(' ')
        }
        write!(file, "{} ", item)?;

        if linebreak == 4 {
            write!(file, "\n")?;
            linebreak = 0;
        }

        linebreak += 1;
    }

    linebreak = 1;
    write!(file, "\n\n-- Unique MAC Adresses\n")?;
    for item in macs {

        write!(file, "{}    ", item)?;

        if linebreak == 4 {
            write!(file, "\n")?;
            linebreak = 0;
        }

        linebreak += 1;
    }

    linebreak = 1;
    write!(file, "\n\n-- Unique Lower Ports \n")?;

    let mut ports = ports.into_iter().collect::<Vec<_>>();
    ports.sort();

    for item in ports {

        if item.0 < 32768 {
            // nicely format the strings in the report 
            let mut item = item.to_string();
            for _ in 0..6-item.len() {
                item.push(' ')
            }
            write!(file, "{} ", item)?;

            if linebreak == 12 {
                write!(file, "\n")?;
                linebreak = 0;
            }

            linebreak += 1;
        }
    }

    Ok(())
}
