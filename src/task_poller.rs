use async_std::channel::{Receiver, RecvError};
use futures_lite::future::FutureExt;
use std::future::Future;
use std::mem::replace;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::task::JoinHandle;

pub struct TaskPoller {
	task_receiver: Receiver<JoinHandle<()>>,
	tasks: Vec<JoinHandle<()>>
}


impl TaskPoller {
	pub fn new(task_receiver: Receiver<JoinHandle<()>>) -> Self {
		Self {
			task_receiver,
			tasks: Vec::new()
		}
	}
}


impl Future for TaskPoller {
	type Output = RecvError;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		match self.task_receiver.recv().poll(cx) {
			Poll::Ready(handle) => match handle {
				Ok(handle) => self.tasks.push(handle),
				Err(e) => return Poll::Ready(e)
			}
			Poll::Pending => {}
		}

		for mut task in replace(&mut self.tasks, Vec::new()) {
			match task.poll(cx) {
				Poll::Ready(_) => {}
				Poll::Pending => self.tasks.push(task)
			}
		}

		Poll::Pending
	}
}
