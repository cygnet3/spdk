use std::{
    panic::UnwindSafe,
    sync::{mpsc, Arc, Mutex},
    thread,
};

pub struct ThreadPool {
    workers: Vec<thread::JoinHandle<()>>,
    sender: mpsc::Sender<Box<dyn FnOnce() + Send + UnwindSafe + 'static>>,
}

type Task = Box<dyn FnOnce() + Send + UnwindSafe + 'static>;

impl ThreadPool {
    pub fn new(size: usize) -> Self {
        let (tx, rx) = mpsc::channel::<Task>();
        let rx = Arc::new(Mutex::new(rx));

        let mut workers = Vec::with_capacity(size);

        for _ in 0..size {
            let rx = Arc::clone(&rx);
            workers.push(thread::spawn(move || loop {
                let task: Task = match rx.lock().expect("poisoned").recv() {
                    Ok(task) => task,
                    Err(_) => {
                        // TODO: log
                        break;
                    }
                };
                if std::panic::catch_unwind(task).is_err() {
                    // TODO: log
                }
            }));
        }
        ThreadPool {
            workers,
            sender: tx,
        }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + UnwindSafe + 'static,
    {
        let _ = self.sender.send(Box::new(f));
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        let _ = &self.sender;
        for worker in &mut self.workers.drain(..) {
            worker.join().unwrap();
        }
    }
}
