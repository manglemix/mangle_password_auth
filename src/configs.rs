use tokio::fs::File;
// use tokio::io::ReadExt;
use std::path::Path;
use simple_serde::{mlist_prelude::*, prelude::*, toml_prelude::*};

use super::*;

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
	pub key_challenge_prefix: String,
	pub salt_len: u8,
	pub min_username_len: u8,
	pub max_username_len: u8,
	pub cleanup_delay: u32,
	pub permissions_path: String,
	pub password_regex: Option<String>,
	pub failed_logins_path: String
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
			key_challenge_prefix: data.deserialize_key_or("key_challenge_prefix", "mangleDB_challenge_")?,
			salt_len: data.deserialize_key_or("salt_len", 32)?,
			min_username_len: data.deserialize_key_or("min_username_len", 8)?,
			max_username_len: data.deserialize_key_or("max_username_len", 16)?,
			cleanup_delay: data.deserialize_key_or("cleanup_delay", 7200u32)?,
			permissions_path: data.deserialize_key_or("permissions_path", "permissions.mlist")?,
			password_regex: data.deserialize_key_opt("password_regex")?,
			failed_logins_path: data.deserialize_key_or("failed_logins_path", "failed_logins.log")?
		})
	}
}


pub async fn read_config_file<T: AsRef<Path>>(path: T) -> Configs {
	let mut file = unwrap_result_or_default_error!(
		File::open(path).await,
		"opening config file"
	);
	let mut data = String::new();
	unwrap_result_or_default_error!(
		file.read_to_string(&mut data).await,
		"reading config file"
	);
	unwrap_result_or_default_error!(
		Configs::deserialize_toml(data),
		"parsing config file"
	)
}

impl_toml_deser!(Configs, ReadableProfile);
