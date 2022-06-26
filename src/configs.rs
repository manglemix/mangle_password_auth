use std::path::Path;

use figment::{Figment, providers::Toml};
use figment::providers::Format;
use serde::Deserialize;

use crate::mangle_rust_utils::Colorize;


#[derive(Deserialize)]
pub struct Configs {
	pub suffix: String,
	pub mount_point: String,
	pub log_path: String,
	pub users_path: String,
	pub used_challenges_path: String,
	pub max_session_duration: u64,
	pub max_pipe_idle_duration: u64,
	pub login_timeout: u64,
	pub max_fails: u8,
	pub roles_path: String
}


pub fn read_config_file<T: AsRef<Path>>(path: T) -> Configs {
	match Figment::new()
		.join(Toml::file(path))
		.merge(("mount_point", "/"))
		.merge(("log_path", "errors.log"))
		.merge(("users_path", "users"))
		.merge(("used_challenges_path", "used_challenges"))
		.merge(("max_session_duration", 1800))
		.merge(("max_pipe_idle_duration", 1800))
		.merge(("login_timeout", 600))
		.merge(("max_fails", 3))
		.merge(("roles_path", "roles"))
		.extract()
	{
		Ok(x) => x,
		Err(e) => {
			error!("Error in config file:\n\t{e}");
			bad_exit!();
		}
	}
}
