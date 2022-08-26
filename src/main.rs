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

///
/// 
/// parse out the data from a pcap file. I only need a few fields for my 
/// use case, as such, this program parses just those fields.
/// 
/// 0xca7
/// 
/// 
/// TODO: add statistics
/// TODO: add command line args


use std::env;
use std::time::Instant;

pub mod util;
pub mod pinfo;
pub mod dumpreader;
pub mod analyze;

fn usage() {
    print!("\n-- NETANALYZE\n");
    print!("-- ./netanalyze [PCAP file]\n");
    print!("-- this will produce:\n");
    print!("-- | report.txt - a short summary of the dump\n");
    print!("-- | graph.png  - shows a graphical overview of the network\n");
    print!("-- | out.png    - a dot file you can use with graphviz \n");
    print!("-- | nx.html    - an interactive graph you can view in a browser\n");
    print!("-- author: 0xca7\n\n");
}

fn main() {
 
    let args: Vec<String> = env::args().collect(); 

    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let capfile = args[1].as_str();

    if !util::check_exists(capfile) {
        print!("error: capture file does not exist\n");
        std::process::exit(1);
    }

    let now = Instant::now();

    let mut cap = dumpreader::open_capture(capfile);
    let packets = dumpreader::parse(&mut cap);

    let packetlist = packets.into_iter().collect::<Vec<_>>();

    print!("[*] took {:?}, {} packets\n", now.elapsed(), packetlist.len());

    print!("[+] reporting...\n");
    let now = Instant::now();

    match analyze::generate_report(&packetlist) {
        Ok(()) => print!("[+] report done\n"),
        Err(e) => eprint!("error: {}\n", e),
    };

    match analyze::dotfile(&packetlist) {
        Ok(()) => print!("[+] writing dotfile done\n"),
        Err(e) => eprint!("error: {}\n", e),
    };

    match analyze::visualize(&packetlist) {
        Ok(()) => print!("[+] visualization done\n"),
        Err(e) => eprint!("error: {}\n", e),
    };

    print!("[*] took {:?}, {} packets\n", now.elapsed(), packetlist.len());

}
