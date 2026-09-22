use std::ops::RangeInclusive;

use bitcoin::absolute::Height;
use futures::channel::mpsc::Receiver;

use crate::scanner::structs::ScanResult;

pub trait Scanner {
    fn scan_blocks(self, range: RangeInclusive<Height>) -> Receiver<ScanResult>;
}
