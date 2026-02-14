use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

pub struct ThreadPool {
    // JoinHandles kept to prevent threads from being detached immediately.
    // Not read directly - threads complete naturally when sender is dropped.
    #[allow(dead_code)]
    workers: Vec<thread::JoinHandle<()>>,
    sender: Option<mpsc::Sender<Box<dyn FnOnce() + Send + 'static>>>,
}

type Task = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        let (tx, rx) = mpsc::channel::<Task>();
        let rx = Arc::new(Mutex::new(rx));

        let mut workers = Vec::with_capacity(size);

        for _ in 0..size {
            let rx = Arc::clone(&rx);
            #[allow(clippy::while_let_loop)]
            workers.push(thread::spawn(move || loop {
                let task: Task = match rx.lock().expect("poisoned").recv() {
                    Ok(task) => task,
                    Err(_) => break,
                };
                task();
            }));
        }
        ThreadPool {
            workers,
            sender: Some(tx),
        }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if let Some(sender) = &self.sender {
            let _ = sender.send(Box::new(f));
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        // Drop the sender to signal workers to exit their recv() loop.
        // Don't join - workers continue processing and send results through
        // their cloned senders. The results iterator will block until all
        // senders are dropped (workers complete).
        self.sender.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn test_results_stream_incrementally() {
        // Create a results channel (simulating the real usage pattern)
        let (results_tx, results_rx) = mpsc::channel::<u32>();

        let pool = ThreadPool::new(4);

        // Submit 4 tasks with staggered completion times
        for i in 0..4u32 {
            let tx = results_tx.clone();
            pool.execute(move || {
                // Task i sleeps for (i+1) * 50ms before sending result
                std::thread::sleep(Duration::from_millis((i as u64 + 1) * 50));
                let _ = tx.send(i);
            });
        }

        // Drop our sender so the iterator will end when all tasks complete
        drop(results_tx);
        // Drop pool to trigger the new Drop behavior (no blocking join)
        drop(pool);

        // Collect results and measure when each arrives
        let start = Instant::now();
        let mut timings = Vec::new();

        for result in results_rx {
            timings.push((result, start.elapsed()));
        }

        // Verify all 4 results received
        assert_eq!(timings.len(), 4);

        // Verify streaming: results should arrive at different times
        // If Drop blocked, all would arrive at ~200ms (after slowest task)
        // With streaming, first should arrive ~50ms, not ~200ms
        let first_arrival = timings.iter().map(|(_, t)| t).min().unwrap();
        let last_arrival = timings.iter().map(|(_, t)| t).max().unwrap();

        // First result should arrive well before last (streaming)
        // Allow some tolerance for thread scheduling
        assert!(
            first_arrival.as_millis() < 150,
            "First result arrived at {:?}, expected < 150ms (streaming)",
            first_arrival
        );
        assert!(
            last_arrival.as_millis() >= 150,
            "Last result arrived at {:?}, expected >= 150ms",
            last_arrival
        );
    }
}
