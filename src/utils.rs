use std::fs::File;
use std::process::Command;
use std::io::{self, BufRead, BufReader};

/// executes tshark to get the pcap into the correct CSV format
pub fn preprocess(pcap_path: &String) {
    let output = Command::new("./captures/conv_csv.sh")
        .arg(pcap_path)
        .output()
        .expect("error running /captures/conv_csv.sh");
    if !output.status.success() {
        print!("[+] failed to exec conversion via tshark\n");
        std::process::exit(1);
    }
}

/// just executes the python program to visualize
/// for now, might be re-done in rust later
pub fn visualize() {
    let output = std::process::Command::new("python3")
        .arg("py/visualize.py")
        .output()
        .expect("failed to execute python visualizer");
        if !output.status.success() {
            print!("[+] error visualization\n");
            std::process::exit(1);
        }
}

/// get the number of lines a file has
pub fn get_line_count(filepath: &str) -> io::Result<usize> {
    let input = File::open(filepath)?;
    let buffered = BufReader::new(input);
    let line_count = buffered.lines().count();
    Ok(line_count)
}

pub fn progress_bar(total: usize, current: usize) {
    let percent = ((total as f32) * (0.1 as f32)) as usize;
    if current % percent == 0 {
        let blocks = (current * 100) / total;
        print!("{} % > ", (current * 100) / total);
        for _ in 0..blocks {
            print!("▮");
        }
        print!("\n");
    }
}