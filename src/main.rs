#![feature(proc_macro_hygiene, decl_macro)]

extern crate rocket;
#[macro_use]
extern crate mangle_rust_utils;

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Error as IOError, ErrorKind, Read};
use std::ops::{Add, Deref};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_std::io::{self, WriteExt};
use async_std::task::block_on;
use mangle_db_config_parse::ask_config_filename;
use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader};
use regex::Regex;
use rocket::{Either, State};
use rocket::fairing::AdHoc;
use rocket::http::{ContentType, Cookie, CookieJar, Status};
use rocket::time::OffsetDateTime;
use rocket_async_compression::Compression;
use simple_serde::PrimitiveSerializer;
use simple_serde::mlist_prelude::MListDeserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use parsing::{PermissionsDeser};

use parsing::{UsedChallenges, UserCredentialData};
use singletons::{Credential, LoginResult, Logins, Permissions, Pipes, SessionID, Sessions, SpecialUsers, UserCreationError};
use configs::read_config_file;

use simple_logger::prelude::*;

mod singletons;
mod configs;
mod parsing;

const MANGLE_DB_CLOSED: &str = "MangleDB has closed the connection";
const RESOURCE_NOT_FOUND: &str = "Resource not found, or you do not have adequate permissions";


declare_logger!(pub LOG, EitherFileOrStderr, 0, );
define_error!(LOG, export);
define_info!(LOG, export);
define_warn!(LOG, export);


fn path_buf_to_segments(path: &PathBuf) -> Vec<String> {
	path.components().map(|x| x.as_os_str().to_str().map(|x| x.to_string())).flatten().collect()
}


macro_rules! write_socket {
    ($socket: expr, $payload: expr) => {
		write_socket!($socket, $payload, DB_CONNECTION)
	};
    ($socket: expr, $payload: expr, either) => {
		write_socket!($socket, $payload, Either::Left(DB_CONNECTION))
	};
    ($socket: expr, $payload: expr, $server_err_msg: expr) => {
		match $socket.write_all($payload).await {
		Ok(_) => {}
		Err(e) => {
			if e.kind() == ErrorKind::BrokenPipe {
				error!("{}", MANGLE_DB_CLOSED);
			} else {
				default_error!(e, "reading from local socket");
			}
			return make_response!(ServerError, $server_err_msg);
		}
	}};
}


macro_rules! read_socket {
	($socket: expr) => {
		read_socket!($socket, DB_CONNECTION)
	};
    ($socket: expr, either) => {
		read_socket!($socket, Either::Left(DB_CONNECTION))
	};
    ($socket: expr, $conn_err_msg: expr) => {{
		let mut size_buffer = [0u8; 5];

		match $socket.read(size_buffer.as_mut_slice()).await {
			Ok(0) => {
				error!("{}", MANGLE_DB_CLOSED);
				return make_response!(ServerError, $conn_err_msg)
			}
			Err(e) => {
				default_error!(e, "reading header from pipe");
				return make_response!(ServerError, $conn_err_msg)
			}
			Ok(_) => {}
		}

		let mut buffer;
		if size_buffer[0] == 0 {
			let size = u32::from_be_bytes([size_buffer[1], size_buffer[2], size_buffer[3], size_buffer[4]]) as usize;
			buffer = vec![0; size];
			if size > 0 {
				match $socket.read_exact(buffer.as_mut_slice()).await {
					Ok(0) => {
						error!("{}", MANGLE_DB_CLOSED);
						return make_response!(ServerError, $conn_err_msg)
					}
					Err(e) => {
						if e.kind() == ErrorKind::BrokenPipe {
							error!("{}", MANGLE_DB_CLOSED);
						} else {
							default_error!(e, "reading from local socket");
						}
						return make_response!(ServerError, $conn_err_msg)
					}
					_ => {}
				}
			}
			buffer.insert(0, 0);

		} else {
			buffer = vec![size_buffer[0]];
		}
		buffer
	}};
}


const BUG_MESSAGE: &str = "We encountered a bug on our end. Please try again later";
const DB_CONNECTION: &str = "We had difficulties connecting to our database. Please try again later";


macro_rules! make_response {
	(ServerError, $reason: expr) => {
		make_response!(Status::InternalServerError, $reason)
	};
	(NotFound, $reason: expr) => {
		make_response!(Status::NotFound, $reason)
	};
	(BadRequest, $reason: expr) => {
		make_response!(Status::BadRequest, $reason)
	};
	(Ok, $reason: expr) => {
		make_response!(Status::Ok, $reason)
	};
	(BUG) => {
		make_response!(NotFound, BUG_MESSAGE)
	};
	(BUG, either) => {
		make_response!(NotFound, Either::Left(BUG_MESSAGE))
	};
    ($code: expr, $reason: expr) => {
		($code, $reason)
	};
}


macro_rules! parse_header {
    ($buffer: expr) => {
		parse_header!($buffer, BUG_MESSAGE)
	};
    ($buffer: expr, either) => {
		parse_header!($buffer, Either::Left(BUG_MESSAGE))
	};
    ($buffer: expr, $err_msg: expr) => {{
		let header = match $buffer.remove(0) {
			Some(x) => x,
			None => {
				error!("Empty response from db");
				return make_response!(ServerError, $err_msg);
			}
		};
		match TryInto::<GatewayResponseHeader>::try_into(header) {
			Ok(x) => x,
			Err(_) => {
				error!("Unrecognised header {header}");
				return make_response!(ServerError, $err_msg);
			}
		}
	}};
}


const SESSION_COOKIE_NAME: &str = "Session-ID";


macro_rules! check_session_id {
    ($session: expr, $cookies: expr) => {
		check_session_id!($session, $cookies, "The Session-ID is malformed", "The Session-ID is invalid or expired")
	};
    ($session: expr, $cookies: expr, either) => {
		check_session_id!($session, $cookies, Either::Left("The Session-ID is malformed"), Either::Left("The Session-ID is invalid or expired"))
	};
    ($session: expr, $cookies: expr, $err_msg1: expr, $err_msg2: expr) => {
		if let Some(cookie) = $cookies.get(SESSION_COOKIE_NAME) {
			let session_id = match SessionID::try_from(cookie.value().to_string()) {
				Ok(x) => x,
				Err(_) => return make_response!(BadRequest, $err_msg1)
			};
			if !$session.is_valid_session(&session_id).await {
				return make_response!(Status::Unauthorized, $err_msg2)
			}
			Some(session_id)
		} else {
			None
		}
	};
}

macro_rules! missing_session {
    () => {
		return make_response!(BadRequest, "Missing Session-ID cookie")
	};
    (either) => {
		return make_response!(BadRequest, Either::Left("Missing Session-ID cookie"))
	};
}


type Response = (Status, &'static str);


struct _GlobalState {
	logins: Arc<Logins>,
	sessions: Arc<Sessions>,
	pipes: Arc<Pipes>,
	special_users: SpecialUsers,
	permissions: Permissions
}


type GlobalState = State<_GlobalState>;


#[rocket::get("/<path..>")]
async fn borrow_resource(path: PathBuf, cookies: &CookieJar<'_>, globals: &GlobalState) -> (Status, Either<&'static str, (ContentType, Vec<u8>)>) {
	if let Some(session) = check_session_id!(globals.sessions, cookies, either) {
		if let Some(username) = globals.sessions.get_session_owner(&session).await {
			if !globals.permissions.can_user_read_here(&username, &path) {
				return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND))
			}
		} else {
			error!("No session owner but session-id was valid!");
			return make_response!(BUG, either)
		}
	} else if !globals.permissions.can_anonymous_read_here(&path) {
		return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND))
	}

	let mut socket = match globals.pipes.take_pipe().await {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "connecting to db");
			return make_response!(ServerError, Either::Left(DB_CONNECTION))
		}
	};

	let mut payload = vec![GatewayRequestHeader::BorrowResource.into()];
	payload.append(&mut path.to_str().unwrap().as_bytes().to_vec());

	write_socket!(socket, payload.as_slice(), either);

	let mut buffer: VecDeque<_> = read_socket!(socket, either).into();

	globals.pipes.return_pipe(socket).await;

	match parse_header!(buffer, either) {
		GatewayResponseHeader::Ok => {}
		GatewayResponseHeader::InternalError => return make_response!(NotFound, Either::Left(BUG_MESSAGE)),
		_ => return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND)),
	}

	let mime_type = match buffer.deserialize_string() {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "parsing mime type from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	let payload_size: u32 = match buffer.deserialize_num() {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "parsing payload size from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	if buffer.len() != payload_size as usize {
		error!("Payload size mismatch:\n\texpected: {}\n\tactual: {}", payload_size, buffer.len());
		return make_response!(ServerError, Either::Left(BUG_MESSAGE))
	}

	(Status::Ok, Either::Right((
		match ContentType::parse_flexible(mime_type.as_str()) {
			Some(x) => x,
			None => {
				error!("Mime type from db is not valid: {}", mime_type);
				return make_response!(ServerError, Either::Left(BUG_MESSAGE))
			}
		},
		Into::<Vec<_>>::into(buffer)
	)))
}


#[rocket::put("/<path..>", data = "<data>")]
async fn put_resource(path: PathBuf, data: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	if let Some(session) = check_session_id!(globals.sessions, cookies) {
		if let Some(username) = globals.sessions.get_session_owner(&session).await {
			if !globals.permissions.can_user_write_here(&username, &path) {
				return make_response!(NotFound, RESOURCE_NOT_FOUND)
			}
		} else {
			error!("No session owner but session-id was valid!");
			return make_response!(BUG)
		}
	} else {
		missing_session!()
	}

	let mut socket = match globals.pipes.take_pipe().await {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "connecting to db");
			return make_response!(ServerError, DB_CONNECTION)
		}
	};

	let mut payload = vec![GatewayRequestHeader::WriteResource.into()];
	let path_str = path.to_str().unwrap();
	payload.append(&mut (path_str.len() as u32).to_be_bytes().to_vec());
	payload.append(&mut (String::from(path_str) + data.as_str()).as_bytes().to_vec());

	write_socket!(socket, payload.as_slice());

	let mut buffer: VecDeque<_> = read_socket!(socket).into();

	globals.pipes.return_pipe(socket).await;

	match parse_header!(buffer) {
		GatewayResponseHeader::Ok => make_response!(Ok, "Resource put successfully"),
		GatewayResponseHeader::InternalError => make_response!(BUG),
		GatewayResponseHeader::NotFound | GatewayResponseHeader::BadPath => make_response!(NotFound, RESOURCE_NOT_FOUND),
		GatewayResponseHeader::BadRequest => unreachable!(),
		GatewayResponseHeader::BadResource => make_response!(BadRequest, "The given resource is not valid")
	}
}


#[rocket::post("/<path..>", data = "<data>")]
async fn post_data(path: PathBuf, data: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> (Status, Either<&'static str, (ContentType, Vec<u8>)>) {
	if let Some(session) = check_session_id!(globals.sessions, cookies, either) {
		if let Some(username) = globals.sessions.get_session_owner(&session).await {
			if !globals.permissions.can_user_write_here(&username, &path) {
				return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND))
			}
		} else {
			error!("No session owner but session-id was valid!");
			return make_response!(BUG, either)
		}
	} else {
		missing_session!(either)
	}

	let mut socket = match globals.pipes.take_pipe().await {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "connecting to db");
			return make_response!(ServerError, Either::Left(DB_CONNECTION))
		}
	};

	let mut payload = vec![GatewayRequestHeader::CustomCommand.into()];
	let path_str = path.to_str().unwrap();
	payload.append(&mut (path_str.len() as u32).to_be_bytes().to_vec());
	payload.append(&mut (String::from(path_str) + data.as_str()).as_bytes().to_vec());

	write_socket!(socket, payload.as_slice(), either);

	let mut buffer: VecDeque<_> = read_socket!(socket, either).into();

	globals.pipes.return_pipe(socket).await;

	match parse_header!(buffer, either) {
		GatewayResponseHeader::Ok => {}
		GatewayResponseHeader::InternalError => return make_response!(NotFound, Either::Left(BUG_MESSAGE)),
		_ => return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND)),
	}

	let mime_type = match buffer.deserialize_string() {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "parsing mime type from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	let payload_size: u32 = match buffer.deserialize_num() {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "parsing payload size from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	if buffer.len() != payload_size as usize {
		error!("Payload size mismatch:\n\texpected: {}\n\tactual: {}", payload_size, buffer.len());
		return make_response!(ServerError, Either::Left(BUG_MESSAGE))
	}

	(Status::Ok, Either::Right((
		match ContentType::parse_flexible(mime_type.as_str()) {
			Some(x) => x,
			None => {
				error!("Mime type from db is not valid: {}", mime_type);
				return make_response!(ServerError, Either::Left(BUG_MESSAGE))
			}
		},
		Into::<Vec<_>>::into(buffer)
	)))
}


#[rocket::get("/users_with_password?<username>&<password>")]
async fn get_session_with_password(username: String, password: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	match globals.logins.try_login_password(&username, password).await {
		LoginResult::Ok => {
			let session_id = globals.sessions.create_session(username).await;
			cookies.add(
				Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
					.expires(OffsetDateTime::from(SystemTime::now().add(globals.sessions.max_session_duration)))
					// .secure(true)	TODO Re-implement!
					.finish()
			);
			make_response!(Ok, "Authentication Successful")
		}
		LoginResult::BadCredentialChallenge => make_response!(Status::Unauthorized, "The given password is incorrect"),
		LoginResult::NonexistentUser => make_response!(Status::Unauthorized, "The given username does not exist"),
		LoginResult::LockedOut => make_response!(Status::Unauthorized, "You have failed to login too many times"),
		LoginResult::UnexpectedCredentials => make_response!(Status::BadRequest, "The user does not support password authentication"),
		_ => unreachable!()
	}
}


#[rocket::get("/users_with_key?<username>&<message>&<signature>")]
async fn get_session_with_key(username: String, message: String, signature: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	let signature = match signature.parse() {
		Ok(x) => x,
		Err(_) => return make_response!(BadRequest, "Invalid signature")
	};
	match globals.logins.try_login_key(&username, message, signature).await {
		LoginResult::Ok => {
			let session_id = globals.sessions.create_session(username).await;
			cookies.add(
				Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
					.expires(OffsetDateTime::from(SystemTime::now().add(globals.sessions.max_session_duration)))
					.secure(true)
					.finish()
			);
			make_response!(Ok, "Authentication Successful")
		}
		LoginResult::BadCredentialChallenge => make_response!(Status::Unauthorized, "The given signature is incorrect"),
		LoginResult::NonexistentUser => make_response!(Status::Unauthorized, "The given username does not exist"),
		LoginResult::LockedOut => make_response!(Status::Unauthorized, "You have failed to login too many times"),
		LoginResult::UsedChallenge => make_response!(Status::Unauthorized, "The given challenge has been used before"),
		LoginResult::UnexpectedCredentials => make_response!(Status::BadRequest, "The user does not support key based authentication")
	}
}


#[rocket::put("/create_user_with_password?<username>&<password>")]
async fn make_user(username: String, password: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	let session_id = match check_session_id!(globals.sessions, cookies) {
		Some(x) => x,
		None => missing_session!()
	};

	match globals.sessions.get_session_owner(&session_id).await {
		Some(creator) => if !globals.special_users.can_user_create_user(&creator) {
			return make_response!(Status::Unauthorized, "You are not authorized to create users")
		}
		None => {
			error!("Session-ID was valid but not associated with a user!");
			return make_response!(BUG)
		}
	}

	match globals.logins.add_user(username, password).await {
		Ok(()) => make_response!(Ok, "User created successfully"),
		Err(e) => match e {
			UserCreationError::ArgonError(e) => {
				default_error!(e, "generating password hash");
				make_response!(BUG)
			},
			UserCreationError::UsernameInUse => make_response!(BadRequest, "Username already in use"),
			UserCreationError::BadPassword => make_response!(BadRequest, "Password is not strong enough"),
			UserCreationError::BadUsername => make_response!(BadRequest, "Username is not alphanumeric or too short or too long")
		}
	}
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
				_GlobalState {
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
