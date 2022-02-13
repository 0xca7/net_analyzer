/// application to analyze a PCAP file
/// and output a summary and graph of it
/// 0xca7

use std::env;
use std::fs::File;
use std::error::Error;
use std::time::Instant;

use chrono::prelude::*;

mod analyze;
use analyze::{DataItem, DumpAnalysis};

mod report;
use report::{write_report, write_graph};

/// read the csv file given by `filepath` and de-dupe the file using 
/// a `HashSet`. This returns unique entries (rows) of the csv.
fn read_csv(filepath: &str) -> Result<DumpAnalysis, Box<dyn Error>> {

    let mut count: usize = 0;
    let mut data = DumpAnalysis::new();

    let file = File::open(filepath)?;
    let mut rdr = csv::Reader::from_reader(file);

    for result in rdr.deserialize() {
        let record: DataItem = result?;
        data.insert_packet(record);
        count += 1;
        if count % 10000 == 0 {
            print!("-- read {} packets\n", count);
        }
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

    if args.len() != 3 {
        usage();
        std::process::exit(1);
    }

    let mut now = Instant::now();
    
    // read the csv and get a hash set out
    let mut data = match read_csv(&args[1]) {
        Ok(data) => data,
        Err(e) => {
            print!("error: {}\n", e);
            std::process::exit(1);
        }
    };

    print!("[+] reading CSV took {:?}\n", now.elapsed());

    now = Instant::now();

    data.analyze();

    print!("[+] analysis took {:?}\n", now.elapsed());

    // create a report file and save it 
    let local: DateTime<Local> = Local::now();
    let filename = format!("results/{}-{}_{}_{}-{}_{}_{}.txt",
        args[2], // this is the filename passed by the user
        local.day(), local.month(), local.year(),
        local.hour(), local.minute(), local.second());


    print!("[+] report will be written as: {}\n", filename);
    write_report(&data, &filename);

    print!("[+] writing graph\n");
    write_graph(&data);

    std::process::Command::new("python3")
        .arg("py/visualize.py")
        .output()
        .expect("failed to execute python visualizer");

    print!("[+] done!\n");

}
