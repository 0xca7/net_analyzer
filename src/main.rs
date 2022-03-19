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

use std::env;
use std::fs::File;
use std::error::Error;
use std::time::Instant;

use chrono::prelude::*;
use csv;

mod analyze;
use analyze::{DataItem, DumpAnalysis};

mod report;
use report::{write_report, write_graph};

mod utils;
use utils::{
    preprocess, 
    visualize, 
    get_line_count, 
    progress_bar
};

/// read the csv file given by `filepath` and de-dupe the file using 
/// a `HashSet`. This returns unique entries (rows) of the csv.
fn read_csv(filepath: &str) -> Result<DumpAnalysis, Box<dyn Error>> {

    let mut count: usize = 0;
    let mut data = DumpAnalysis::new();

    // get the number of lines in the csv minus the header line
    let no_lines = get_line_count(filepath)?;

    let file = File::open(filepath)?;
    let mut rdr = csv::Reader::from_reader(file);

    for result in rdr.deserialize() {
        let record: DataItem = result?;
        data.insert_packet(record);
        count += 1;
        progress_bar(no_lines, count);
    }

    print!("[+] read {} packets from csv\n", count);
    Ok(data)

}

fn usage() {
    print!("USAGE:   netanalyze [PATH-TO-CSV-FILE] [NAME-OF-REPORT]\n");
    print!("Example: netanalyze captures/test.csv report\n");
    print!("-- to convert to CSV with the correct headers,\n");
    print!("-- use the script \"captures/conv_csv.sh\"\n");
}

fn main() {

    let args: Vec<String> = env::args().collect();

    // check the user supplied arguments
    if args.len() != 3 {
        usage();
        std::process::exit(1);
    } else {
        // check if the file to parse even exists
        if !std::path::Path::new(&args[1]).exists() {
            print!("file {} does not exist\n", args[1]);
            std::process::exit(1);
        }
    }

    let mut now = Instant::now();

    // get the pcap to appropriate csv format
    print!("[+] converting to CSV\n");
    preprocess(&args[1]);
    print!("[+] conversion took {:?}\n", now.elapsed());


    // read the csv and get a hash set (de-duped)
    now = Instant::now();
    let mut filepath : String = args[1].clone();
    filepath.push_str(".csv");

    print!("[+] reading CSV: {}\n", filepath);
    let mut data = match read_csv(&filepath) {
        Ok(data) => data,
        Err(e) => {
            print!("error: {}\n", e);
            std::process::exit(1);
        }
    };

    print!("[+] reading CSV took {:?}\n", now.elapsed());

    now = Instant::now();

    print!("[+] analyzing data\n");
    data.analyze();
    print!("[+] analysis took {:?}\n", now.elapsed());

    // create a report file and save it 
    let local: DateTime<Local> = Local::now();
    let filename = 
        format!("results/{}-{}_{}_{}-{}_{}_{}.txt",
        args[2], // this is the filename passed by the user
        local.day(), local.month(), local.year(),
        local.hour(), local.minute(), local.second());

    print!("[+] report will be written as: {}\n", filename);
    write_report(&data, &filename);

    print!("[+] writing graph\n");
    write_graph(&data);

    now = Instant::now();
    print!("[+] running visualizer\n");
    visualize();
    print!("[+] visualization took {:?}\n", now.elapsed());

    print!("[+] done!\n");

}
