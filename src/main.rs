#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate mangle_rust_utils;
extern crate rocket;

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::{Error as IOError, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

use tokio::io::{AsyncReadExt};
use mangle_db_config_parse::ask_config_filename;
use regex::Regex;
use rocket::fairing::AdHoc;
use rocket_async_compression::Compression;
use simple_logger::formatters::default_format;
use simple_logger::prelude::*;
use simple_serde::mlist_prelude::MListDeserialize;
use tokio::select;

use configs::read_config_file;
use methods::auth::{get_session_with_key, get_session_with_password, make_user};
use methods::getters::{borrow_resource, directory_tools};
use methods::setters::{post_data, put_resource};
use parsing::PermissionsDeser;
use parsing::{UsedChallenges, UserCredentialData};
use singletons::{Credential, Logins, Permissions, Pipes, Sessions, SpecialUsers};

mod singletons;
mod configs;
mod parsing;


declare_logger!([pub] LOG);
define_error!(crate::LOG, trace, export);
define_info!(crate::LOG, export);
define_warn!(crate::LOG, export);

mod methods;


fn block_on<F: Future + Send + 'static>(f: F) -> F::Output
	where F::Output: Send + 'static
{
	std::thread::spawn(move || {
		tokio::runtime::Runtime::new().unwrap().block_on(f)
	}).join().unwrap()
}


fn path_buf_to_segments(path: &PathBuf) -> Vec<String> {
	path.components().map(|x| x.as_os_str().to_str().map(|x| x.to_string())).flatten().collect()
}


#[rocket::main]
async fn main() {
	let stderr_handle = LOG.attach_stderr(default_format, vec![], true);

	let config_path = ask_config_filename("Mangle Password Auth", "auth_config.toml");
	info!("Using {} as a config file", config_path);
	let configs = read_config_file(config_path);

	let mut users_file = unwrap_result_or_default_error!(
		File::open(configs.users_path),
		"opening users file"
	);

	let mut userdata = String::new();
	unwrap_result_or_default_error!(
		users_file.read_to_string(&mut userdata),
		"reading users file"
	);
	drop(users_file);

	let mut used_challenges = String::new();
	match File::open(configs.used_challenges_path) {
		Ok(mut file) => {
			unwrap_result_or_default_error!(
				file.read_to_string(&mut used_challenges),
				"reading used challenges file"
			);
		}
		Err(e) => match e.kind() {
			ErrorKind::NotFound => {}
			_ => default_error!(e, "opening used challenges file")
		}
	};

	let used_challenges = UsedChallenges::from_str(used_challenges.as_str()).unwrap().0;
	let userdata: HashMap<String, UserCredentialData> = unwrap_result_or_default_error!(
		simple_serde::toml::TOMLDeserialize::deserialize_toml(userdata),
		"parsing users file"
	);

	let mut user_cred_map = HashMap::new();
	let mut privileged = HashMap::new();

	for (username, cred_data) in userdata {
		if cred_data.privileges.is_empty() {
			user_cred_map.insert(username, cred_data.cred);
		} else {
			user_cred_map.insert(username.clone(), cred_data.cred);
			privileged.insert(username, cred_data.privileges);
		}
	}

	let mut permissions_file = unwrap_result_or_default_error!(
		File::open(configs.permissions_path),
		"opening permissions file"
	);

	let mut permissions_data = String::new();
	unwrap_result_or_default_error!(
		permissions_file.read_to_string(&mut permissions_data),
		"reading permissions file"
	);
	drop(permissions_file);

	let mut permissions = unwrap_result_or_default_error!(
		PermissionsDeser::deserialize_mlist(permissions_data),
		"parsing permissions file"
	);

	singletons::FAILED_LOGINS.attach_log_file(configs.failed_logins_path, default_format, vec![], true).expect("Error opening failed logins log file");

	let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

	let mut user_exited = false;
	select! {
		// server
		res = rocket::build()
			.mount(configs.mount_point, rocket::routes![
				get_session_with_password,
				get_session_with_key,
				directory_tools,
				borrow_resource,
				put_resource,
				make_user,
				post_data
			])
			.attach(AdHoc::on_liftoff("notify_liftoff", |_| Box::pin(async move {
				drop(ready_tx);
			})))
			.attach(Compression::fairing())
			.manage(
				methods::_GlobalState {
					logins: Logins::new(
						user_cred_map,
						Duration::from_secs(configs.login_timeout),
						configs.max_fails,
						used_challenges,
						configs.key_challenge_prefix,
						configs.salt_len,
						configs.min_username_len,
						configs.max_username_len,
						configs.cleanup_delay,
						configs.password_regex.map(|x| { block_on(async move { unwrap_result_or_default_error!(Regex::new(x.as_str()), "parsing password regex") }) })
					),
					sessions: Sessions::new(Duration::from_secs(configs.max_session_duration), configs.cleanup_delay),
					pipes: Pipes::new(configs.suffix, configs.cleanup_delay, true),
					special_users: SpecialUsers::new(privileged),
					permissions: Permissions::new(
						permissions.get_public_read_paths(),
						permissions.get_all_users_home_read_paths(),
						permissions.get_all_users_home_write_paths(),
						permissions.get_all_users_extern_read_paths(),
						permissions.get_all_users_extern_write_paths(),
						unwrap_option_or_msg!(
							permissions.get_user_home_parent(),
							"UserHomeParent was not configured"
						),
						permissions.get_users_read_paths(),
						permissions.get_users_write_paths(),
					)
				}
			)
			.launch() => {
			if let Err(e) = res {
				println!();
				default_error!(e, "serving http");
			}
			println!();
		}
		// stdin
		() = async {
			LOG.attach_log_file(configs.log_path, default_format, vec![], true).expect("Error opening log file");
			let _ = ready_rx.recv().await;
			warn!("Listener started up!");
			sleep(Duration::new(0, 100));
			stderr_handle.pause();

			let mut stdin = tokio::io::stdin();
			let mut stdout = std::io::stdout();

			loop {
				print!(">>> ");
				stdout.flush().unwrap();

				let mut line = vec![0; 1024];
				match stdin.read(&mut line).await {
					Ok(0) => return,
					Ok(n) => line.split_off(n),
					Err(_) => continue
				};
				let line = match String::from_utf8(line) {
					Ok(x) => x,
					Err(_) => {
						println!("The given command was not valid utf8");
						continue
					}
				};

				// TODO Add more commands
				match line.trim() {
					"exit" => {
						user_exited = true;
						return
					}
					_ => {}
				}
			}
		} => {},
	}
	;

	stderr_handle.unpause();
	sleep(Duration::new(0, 100));
	if user_exited {
		warn!("User exited!")
	}
	warn!("Exit Successful");
}
