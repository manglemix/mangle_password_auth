use std::fs::File;
use std::io::Read;
use std::path::Path;

use simple_serde::{prelude::*, toml_prelude::*};

use crate::mangle_rust_utils::Colorize;


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
}


impl Deserialize<ReadableProfile> for Configs {
	fn deserialize<T: Serializer>(data: &mut T) -> Result<Self, DeserializationError> {
		Ok(Self {
			suffix: data.deserialize_key("suffix")?,
			mount_point: data.deserialize_key_or("mount_point", "/")?,
			log_path: data.deserialize_key_or("log_path", "errors.log")?,
			users_path: data.deserialize_key_or("users_path", "users")?,
			used_challenges_path: data.deserialize_key_or("used_challenges_path", "used_challenges")?,
			max_session_duration: data.deserialize_key_or("max_session_duration", 1800u64)?,
			max_pipe_idle_duration: data.deserialize_key_or("max_pipe_idle_duration", 1800u64)?,
			login_timeout: data.deserialize_key_or("login_timeout", 600u64)?,
			max_fails: data.deserialize_key_or("max_fails", 3u8)?,
		})
	}
}

impl_toml_deser!(Configs, ReadableProfile);


pub fn read_config_file<T: AsRef<Path>>(path: T) -> Configs {
	let mut file = unwrap_result_or_default_error!(
		File::open(path),
		"opening config file"
	);
	let mut data = String::new();
	unwrap_result_or_default_error!(
		file.read_to_string(&mut data),
		"reading config file"
	);
	unwrap_result_or_default_error!(
		Configs::deserialize_toml(data),
		"parsing config file"
	)
}

