#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate mangle_rust_utils;
#[macro_use]
extern crate rocket;

use std::fs::File;
use std::io::{Error as IOError, ErrorKind, Read};
use std::ops::Deref;
use std::path::PathBuf;

use async_std::io::{self, WriteExt};
use ed25519_dalek::Signature;
use lazy_static::lazy_static;
use mangle_db_config_parse::ask_config_filename;
use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader};
use mangle_rust_utils::setup_logger_file;
use rocket::fairing::AdHoc;
use rocket::http::Status;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;

use crate::auth_state::{AddUserError, AuthState};
use crate::configs::read_config_file;
use crate::guards::{CanCreateUser, MutexBiPipe};
use crate::mangle_rust_utils::Colorize;

mod auth_state;
mod configs;
mod guards;

const MANGLE_DB_CLOSED: &str = "MangleDB has closed the connections";


lazy_static! {
	static ref AUTH_STATE: AuthState = AuthState::new();
}


macro_rules! write_socket {
    ($socket: expr, $payload: expr) => {
		match $socket.write_all($payload).await {
		Ok(_) => {}
		Err(e) => {
			if e.kind() == ErrorKind::BrokenPipe {
				log_error!("{}", MANGLE_DB_CLOSED);
			} else {
				log_default_error!(e, "reading from local socket");
			}
			return Err(Status::InternalServerError);
		}
	}
	};
}


macro_rules! read_socket {
    ($socket: expr, $buffer_size: literal) => {{
		let mut buffer = vec![0; $buffer_size];
		match $socket.read(buffer.as_mut_slice()).await {
			Ok(0) => {
				log_error!("{}", MANGLE_DB_CLOSED);
				return Err(Status::InternalServerError);
			}
			Ok(n) => buffer = buffer[0..n].to_vec(),
			Err(e) => {
				if e.kind() == ErrorKind::BrokenPipe {
					log_error!("{}", MANGLE_DB_CLOSED);
				} else {
					log_default_error!(e, "reading from local socket");
				}
				return Err(Status::InternalServerError);
			}
		}
		buffer
	}};
	($socket: expr) => {
		read_socket!($socket, 128)
	}
}


macro_rules! parse_header {
    ($buffer: expr) => {{
		let header = $buffer.remove(0);
		match TryInto::<GatewayResponseHeader>::try_into(header) {
			Ok(x) => x,
			Err(_) => {
				log_error!("Unrecognised header {header}");
				return Err(Status::InternalServerError);
			}
		}
	}};
}


#[get("/<path..>")]
async fn borrow_resource(bipipe: MutexBiPipe, path: PathBuf) -> Result<String, Status> {
	let mut socket = bipipe.lock().await;

	let mut payload = vec![GatewayRequestHeader::BorrowResource.into()];
	payload.append(&mut path.to_str().unwrap().as_bytes().to_vec());

	write_socket!(socket, payload.as_slice());

	let mut buffer = read_socket!(socket);

	match parse_header!(buffer) {
		GatewayResponseHeader::Ok => {}
		_ => return Err(Status::NotFound),
	}

	String::from_utf8(buffer).map_err(|e| {
		log_default_error!(e, "deserializing resource");
		Status::InternalServerError
	})
}


#[put("/<path..>", data = "<data>")]
async fn put_resource(bipipe: MutexBiPipe, path: PathBuf, data: String) -> Result<&'static str, Status> {
	let mut socket = bipipe.lock().await;

	let mut payload = vec![GatewayRequestHeader::WriteResource.into()];
	let path_str = path.to_str().unwrap();
	payload.append(&mut (path_str.len() as u32).to_be_bytes().to_vec());
	payload.append(&mut (String::from(path_str) + data.as_str()).as_bytes().to_vec());

	write_socket!(socket, payload.as_slice());

	let mut buffer = read_socket!(socket);

	match parse_header!(buffer) {
		GatewayResponseHeader::Ok => {}
		_ => return Err(Status::NotFound),
	}

	Ok("put success")
}


#[get("/users_with_password?<username>&<password>")]
async fn get_session_with_password(username: String, password: String) -> Result<String, Status> {
	if AUTH_STATE.is_user_locked_out(&username).await {
		return Err(Status::TooManyRequests)
	}

	match AUTH_STATE.is_valid_password(&username, &password).await {
		Ok(x) => if !x {
			AUTH_STATE.increment_failed_login(&username).await;
			return Err(Status::Unauthorized)
		}
		Err(e) => {
			log_default_error!(e, "validating password for {username}:{password}");
			return Err(Status::InternalServerError)
		}
	}

	Ok(AUTH_STATE.get_session_id(&username).await.deref().clone())
}


#[get("/users_with_key?<username>&<challenge>&<signature>")]
async fn get_session_with_key(username: String, challenge: String, signature: String) -> Result<String, Status> {
	if AUTH_STATE.is_user_locked_out(&username).await {
		return Err(Status::TooManyRequests)
	}

	let bytes = match base64::decode_config(signature.clone(), base64::URL_SAFE_NO_PAD) {
		Ok(x) => x,
		Err(_) => return Err(Status::BadRequest)
	};

	let signature = match Signature::from_bytes(bytes.as_slice()) {
		Ok(x) => x,
		Err(_) => return Err(Status::BadRequest)
	};

	if !AUTH_STATE.is_valid_key(&username, challenge, signature).await {
		AUTH_STATE.lockout_user(&username).await;
		return Err(Status::Unauthorized);
	}

	Ok(AUTH_STATE.get_session_id(&username).await.deref().clone())
}


#[put("/create_user_with_password?<username>&<password>")]
async fn make_user(_can_create: CanCreateUser, username: String, password: String) -> Result<&'static str, Status> {
	match AUTH_STATE.add_user(username, password, vec![String::from("player")]).await {
		Ok(()) => Ok("user added successfully"),
		Err(e) => {
			match e {
				AddUserError::HashError(e) => log_default_error!(e, "generating password hash"),
				AddUserError::NonexistentRole(role) => log_error!("Tried to create user with nonexistent role: {role}"),
				AddUserError::UserExists => return Ok("username is already used"),
				AddUserError::BadName => return Ok("bad username")
			}
			Err(Status::InternalServerError)
		}
	}
}


#[tokio::main]
async fn main() {
	let config_path = ask_config_filename("Mangle Password Auth", "auth_config");

	info!("Using {} as a config file", config_path);
	let configs = read_config_file(config_path);

	let mut users_file = unwrap_result_or_default_error!(
		File::open(&configs.users_path),
		"opening users file"
	);

	let mut userdata = String::new();
	unwrap_result_or_default_error!(
		users_file.read_to_string(&mut userdata),
		"reading users file"
	);
	drop(users_file);

	let mut used_challenges_file = unwrap_result_or_default_error!(
		File::open(&configs.used_challenges_path),
		"opening used_challenges file"
	);

	let mut used_challenges = String::new();
	unwrap_result_or_default_error!(
		used_challenges_file.read_to_string(&mut used_challenges),
		"reading used_challenges file"
	);
	drop(used_challenges_file);

	let mut roles_file = unwrap_result_or_default_error!(
		File::open(&configs.roles_path),
		"opening roles file"
	);

	let mut roles = String::new();
	unwrap_result_or_default_error!(
		roles_file.read_to_string(&mut roles),
		"reading roles file"
	);
	drop(roles_file);

	// info!("Binding to {bind_addr} on {}", &configs.mount_point);

	AUTH_STATE.populate(
		userdata,
		used_challenges,
		String::from("mangleDB_") + configs.suffix.as_str(),
		roles,
		configs.login_timeout,
		configs.max_fails,
		configs.max_pipe_idle_duration,
		configs.max_session_duration
	).await;

	setup_logger_file(configs.log_path);

	info!("Listener spinning up!");

	let (ready_tx, ready_rx) = async_std::channel::unbounded::<()>();

	select! {
		// server
		res = rocket::build()
			.mount(configs.mount_point, routes![
				get_session_with_password,
				get_session_with_key,
				borrow_resource,
				put_resource,
				make_user
			])
			.attach(AdHoc::on_liftoff("notify_liftoff", |_| Box::pin(async move {
				log_info!("Listener started up!");
				info!("Listener started up!");
				drop(ready_tx);
			})))
			.launch() => {
			if let Err(e) = res {
				log_default_error!(e, "serving http");
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
						default_error!(e, "reading stdin");
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

	warn!("Exiting...");
	log_info!("Listener exiting!");

	unwrap_result_or_default_error!(
		AUTH_STATE.write_userdata(
			&mut unwrap_result_or_default_error!(
				File::create(configs.users_path),
				"opening users file"
			)
		).await,
		"writing to users file"
	);

	unwrap_result_or_default_error!(
		AUTH_STATE.write_used_challenges(
			&mut unwrap_result_or_default_error!(
				File::create(configs.used_challenges_path),
				"opening used_challenges file"
			)
		).await,
		"writing to users file"
	);

	warn!("Exit Successful!");
	log_info!("Listener exited!");
}
