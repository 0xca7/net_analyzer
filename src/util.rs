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
use std::path::Path;
use std::time::Duration;
use std::sync::{Arc, Mutex};

// print progress in this interval
const PROGRESS_INTERVAL_TIME: u32 = 250000000;

/// check if the path in `fname` exists or not
pub fn check_exists(fname: &str) -> bool {
    Path::new(fname).exists()
}

/// show progress for packet parsing every `x` nanoseconds
pub fn progressbar(state: Arc<Mutex<(bool, u64)>>) {

    let sleep_time = Duration::new(0, PROGRESS_INTERVAL_TIME);

    loop {

        let state = state.lock().unwrap();
        if !state.0 {
            break;
        }

        print!("... {} packets parsed so far\n", state.1);
        drop(state);
        thread::sleep(sleep_time);
    }

}