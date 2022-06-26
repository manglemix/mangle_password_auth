use std::path::Path;
use serde::{Deserialize};
use figment::{Figment, providers::{Toml}};
use figment::providers::Format;


#[derive(Deserialize)]
pub struct Configs {
	pub bind_addr: String,
	pub suffix: String,
	pub mount_point: String,
	pub log_path: String,
	pub users_path: String,
	pub used_challenges_path: String,
	pub max_session_duration: u32,
	pub max_pipe_idle_duration: u32
}


pub fn read_config_file<T: AsRef<Path>>(path: T) -> Configs {
	match Figment::new()
		.merge(("mount_point", "/"))
		.merge(("log_path", "errors.log"))
		.merge(("users_path", "users"))
		.merge(("used_challenges_path", "used_challenges"))
		.merge(("max_session_duration", 1800))
		.merge(("max_pipe_idle_duration", 1800))
		.merge(Toml::file(path))
		.extract()
	{
		Ok(x) => x,
		Err(e) => {
			eprintln!("\t{e}");
			bad_exit!();
		}
	}
}
