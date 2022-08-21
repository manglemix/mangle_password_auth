#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate mangle_rust_utils;
extern crate rocket;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Error as IOError, ErrorKind, Read};
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use async_std::io::{self, WriteExt};
use async_std::task::block_on;
use mangle_db_config_parse::ask_config_filename;
use regex::Regex;
use rocket::fairing::AdHoc;
use rocket_async_compression::Compression;
use simple_logger::prelude::*;
use simple_serde::mlist_prelude::MListDeserialize;
use tokio::select;

use configs::read_config_file;
use methods::auth::{get_session_with_key, get_session_with_password, make_user};
use methods::getters::borrow_resource;
use methods::setters::{post_data, put_resource};
use parsing::PermissionsDeser;
use parsing::{UsedChallenges, UserCredentialData};
use singletons::{Credential, Logins, Permissions, Pipes, Sessions, SpecialUsers};

mod singletons;
mod configs;
mod parsing;


declare_logger!(pub LOG, EitherFileOrStderr, 0, );
define_error!(crate::LOG, export);
define_info!(crate::LOG, export);
define_warn!(crate::LOG, export);

mod methods;

fn path_buf_to_segments(path: &PathBuf) -> Vec<String> {
	path.components().map(|x| x.as_os_str().to_str().map(|x| x.to_string())).flatten().collect()
}


#[rocket::main]
async fn main() {
	LOG.init_stderr().await;

	let config_path = ask_config_filename("Mangle Password Auth", "auth_config.toml");
	info!("Using {} as a config file", config_path);
	let configs = read_config_file(config_path).await;

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

	LOG.open_log_file(configs.log_path).await.expect("Error opening log file");
	singletons::FAILED_LOGINS.open_log_file(configs.failed_logins_path).await.expect("Error opening failed logins log file");

	let (ready_tx, ready_rx) = async_std::channel::unbounded::<()>();

	select! {
		// server
		res = rocket::build()
			.mount(configs.mount_point, rocket::routes![
				get_session_with_password,
				get_session_with_key,
				borrow_resource,
				put_resource,
				make_user,
				post_data
			])
			.attach(AdHoc::on_liftoff("notify_liftoff", |_| Box::pin(async move {
				warn!("Listener started up!");
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
						configs.password_regex.map(|x| { block_on(async { unwrap_result_or_default_error!(Regex::new(x.as_str()), "parsing password regex") }) })
					),
					sessions: Sessions::new(Duration::from_secs(configs.max_session_duration), configs.cleanup_delay),
					pipes: Pipes::new(configs.suffix, configs.cleanup_delay),
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
			let _ = ready_rx.recv().await;	// wait for rocket to launch
			drop(ready_rx);
			let stdin = io::stdin();
			
			'main: loop {
				print!(">>> ");
				if io::stdout().flush().await.is_err() {
					continue;
				}
				
				let mut line = String::new();
				match stdin.read_line(&mut line).await {
					Ok(_) => {},
					Err(e) => {
						error!("error reading stdin: {:?}", e);
						continue;
					}
				}
				
				// trimming end
				loop {
					match line.pop() {
						Some(char) => if char.is_alphanumeric() {
							line += String::from(char).as_str();
							break
						}
						None => continue 'main
					}
				}
				
				// TODO Add more commands
				match line.as_str() {
					"exit" => break,
					_ => {}
				}
			};
		} => {},
	}
	;

	warn!("Exit Successful");
	LOG.init_stderr().await;
	warn!("Exit Successful");
}
