#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate mangle_rust_utils;

use std::collections::{HashMap, VecDeque};
use std::fs::{File};
use std::hint::unreachable_unchecked;
use std::io::{Error as IOError, ErrorKind, Read};
use std::ops::{Add, Deref};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_std::io::{self, WriteExt};
use mangle_db_config_parse::ask_config_filename;
use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader};
use mangle_rust_utils::setup_logger_file;
use rocket::Either;
use rocket::fairing::AdHoc;
use rocket::http::{ContentType, Cookie, CookieJar, Status};
use rocket::time::OffsetDateTime;
use rocket_async_compression::Compression;
use simple_serde::PrimitiveSerializer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;

use crate::singletons::{LoginResult, Logins, Pipes, Sessions, SpecialUsers, UserCreationError, SessionID, Credential};
use crate::configs::read_config_file;
use crate::mangle_rust_utils::Colorize;

mod singletons;
mod configs;
mod parsing;

use crate::parsing::{UsedChallenges, UserCredentialData};

const MANGLE_DB_CLOSED: &str = "MangleDB has closed the connection";


struct OptimizedOption<T>(Option<T>);


impl<T> OptimizedOption<T> {
	const fn empty() -> Self {
		Self(None)
	}

	fn write(&mut self, value: T) {
		self.0 = Some(value);
	}
}


impl<T> Deref for OptimizedOption<T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		unsafe {
			match &self.0 {
				None => unreachable_unchecked(),
				Some(x) => x
			}
		}
	}
}


static mut LOGINS: OptimizedOption<Logins> = OptimizedOption::empty();
static mut PIPES: OptimizedOption<Pipes> = OptimizedOption::empty();
static mut SESSIONS: OptimizedOption<Sessions> = OptimizedOption::empty();
static mut SPECIALS: OptimizedOption<SpecialUsers> = OptimizedOption::empty();


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
				log_error!("{}", MANGLE_DB_CLOSED);
			} else {
				log_default_error!(e, "reading from local socket");
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
				log_error!("{}", MANGLE_DB_CLOSED);
				return make_response!(ServerError, $conn_err_msg)
			}
			Err(e) => {
				log_default_error!(e, "reading header from pipe");
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
						log_error!("{}", MANGLE_DB_CLOSED);
						return make_response!(ServerError, $conn_err_msg)
					}
					Err(e) => {
						if e.kind() == ErrorKind::BrokenPipe {
							log_error!("{}", MANGLE_DB_CLOSED);
						} else {
							log_default_error!(e, "reading from local socket");
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
				log_error!("Empty response from db");
				return make_response!(ServerError, $err_msg);
			}
		};
		match TryInto::<GatewayResponseHeader>::try_into(header) {
			Ok(x) => x,
			Err(_) => {
				log_error!("Unrecognised header {header}");
				return make_response!(ServerError, $err_msg);
			}
		}
	}};
}


const SESSION_COOKIE_NAME: &str = "Session-ID";


macro_rules! check_session_id {
    ($cookies: expr) => {
		check_session_id!($cookies, "The Session-ID is malformed", "The Session-ID is invalid or expired", "Missing Session-ID cookie")
	};
    ($cookies: expr, either) => {
		check_session_id!($cookies, Either::Left("The Session-ID is malformed"), Either::Left("The Session-ID is invalid or expired"), Either::Left("Missing Session-ID cookie"))
	};
    ($cookies: expr, $err_msg1: expr, $err_msg2: expr, $err_msg3: expr) => {
		if let Some(cookie) = $cookies.get(SESSION_COOKIE_NAME) {
			let session_id = match SessionID::try_from(cookie.value().to_string()) {
				Ok(x) => x,
				Err(_) => return make_response!(BadRequest, $err_msg1)
			};
			if !unsafe { SESSIONS.is_valid_session(&session_id) }.await {
				return make_response!(Status::Unauthorized, $err_msg2)
			}
			session_id
		} else {
			return make_response!(BadRequest, $err_msg3)
		}
	};
}

type Response = (Status, &'static str);


#[get("/<path..>")]
async fn borrow_resource(path: PathBuf, cookies: &CookieJar<'_>) -> (Status, Either<&'static str, (ContentType, Vec<u8>)>) {
	check_session_id!(cookies, either);

	let mut socket = match unsafe { PIPES.take_pipe() }.await {
		Ok(x) => x,
		Err(e) => {
			log_default_error!(e, "connecting to db");
			return make_response!(ServerError, Either::Left(DB_CONNECTION))
		}
	};

	let mut payload = vec![GatewayRequestHeader::BorrowResource.into()];
	payload.append(&mut path.to_str().unwrap().as_bytes().to_vec());

	write_socket!(socket, payload.as_slice(), either);

	let mut buffer: VecDeque<_> = read_socket!(socket, either).into();

	unsafe { PIPES.return_pipe(socket) }.await;

	match parse_header!(buffer, either) {
		GatewayResponseHeader::Ok => {}
		GatewayResponseHeader::InternalError => return make_response!(NotFound, Either::Left(BUG_MESSAGE)),
		_ => return make_response!(NotFound, Either::Left("The requested resource could not be found")),
	}

	let mime_type = match buffer.deserialize_string() {
		Ok(x) => x,
		Err(e) => {
			log_default_error!(e, "parsing mime type from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	let payload_size: u32 = match buffer.deserialize_num() {
		Ok(x) => x,
		Err(e) => {
			log_default_error!(e, "parsing payload size from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	if buffer.len() != payload_size as usize {
		log_error!("Payload size mismatch:\n\texpected: {}\n\tactual: {}", payload_size, buffer.len());
		return make_response!(ServerError, Either::Left(BUG_MESSAGE))
	}

	(Status::Ok, Either::Right((
		match ContentType::parse_flexible(mime_type.as_str()) {
			Some(x) => x,
			None => {
				log_error!("Mime type from db is not valid: {}", mime_type);
				return make_response!(ServerError, Either::Left(BUG_MESSAGE))
			}
		},
		Into::<Vec<_>>::into(buffer)
	)))
}


#[put("/<path..>", data = "<data>")]
async fn put_resource(path: PathBuf, data: String, cookies: &CookieJar<'_>) -> Response {
	check_session_id!(cookies);
	let mut socket = match unsafe { PIPES.take_pipe() }.await {
		Ok(x) => x,
		Err(e) => {
			log_default_error!(e, "connecting to db");
			return make_response!(ServerError, DB_CONNECTION)
		}
	};

	let mut payload = vec![GatewayRequestHeader::WriteResource.into()];
	let path_str = path.to_str().unwrap();
	payload.append(&mut (path_str.len() as u32).to_be_bytes().to_vec());
	payload.append(&mut (String::from(path_str) + data.as_str()).as_bytes().to_vec());

	write_socket!(socket, payload.as_slice());

	let mut buffer: VecDeque<_> = read_socket!(socket).into();

	unsafe { PIPES.return_pipe(socket) }.await;

	match parse_header!(buffer) {
		GatewayResponseHeader::Ok => make_response!(Ok, "Resource put successfully"),
		GatewayResponseHeader::InternalError => make_response!(BUG),
		GatewayResponseHeader::NotFound | GatewayResponseHeader::BadPath => make_response!(NotFound, "The given path could not be found"),
		GatewayResponseHeader::BadRequest => unreachable!(),
		GatewayResponseHeader::BadResource => make_response!(BadRequest, "The given resource is not valid")
	}
}


#[get("/users_with_password?<username>&<password>")]
async fn get_session_with_password(username: String, password: String, cookies: &CookieJar<'_>) -> Response {
	match unsafe { LOGINS.try_login_password(&username, password) }.await {
		LoginResult::Ok => {
			let session_id = unsafe { SESSIONS.create_session(username) }.await;
			cookies.add(
				Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
					.expires(OffsetDateTime::from(SystemTime::now().add(unsafe { SESSIONS.max_session_duration }.clone())))
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


#[get("/users_with_key?<username>&<message>&<signature>")]
async fn get_session_with_key(username: String, message: String, signature: String, cookies: &CookieJar<'_>) -> Response {
	let signature = match signature.parse() {
		Ok(x) => x,
		Err(_) => return make_response!(BadRequest, "Invalid signature")
	};
	match unsafe { LOGINS.try_login_key(&username, message, signature) }.await {
		LoginResult::Ok => {
			let session_id = unsafe { SESSIONS.create_session(username) }.await;
			cookies.add(
				Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
					.expires(OffsetDateTime::from(SystemTime::now().add(unsafe { SESSIONS.max_session_duration }.clone())))
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


#[put("/create_user_with_password?<username>&<password>")]
async fn make_user(username: String, password: String, cookies: &CookieJar<'_>) -> Response {
	let session_id = check_session_id!(cookies);
	match unsafe { SESSIONS.get_session_owner(&session_id) }.await {
		Some(creator) => if !unsafe { SPECIALS.can_user_create_user(&creator) } {
			return make_response!(Status::Unauthorized, "You are not authorized to create users")
		}
		None => {
			log_error!("Session-ID was valid but not associated with a user!");
			return make_response!(BUG)
		}
	}

	match unsafe { LOGINS.add_user(username, password) }.await {
		Ok(()) => make_response!(Ok, "User created successfully"),
		Err(e) => match e {
			UserCreationError::ArgonError(e) => {
				log_default_error!(e, "generating password hash");
				make_response!(BUG)
			},
			UserCreationError::UsernameInUse => make_response!(BadRequest, "Username already in use"),
			UserCreationError::BadPassword => make_response!(BadRequest, "Password is not strong enough"),
		}
	}
}


#[rocket::main]
async fn main() {
	let config_path = ask_config_filename("Mangle Password Auth", "auth_config.toml");
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
		let username = Arc::new(username);

		if cred_data.privileges.is_empty() {
			user_cred_map.insert(username, Credential::PasswordHash(cred_data.hash));
		} else {
			user_cred_map.insert(username.clone(), Credential::PasswordHash(cred_data.hash));
			privileged.insert(username, cred_data.privileges);
		}
	}

	unsafe {
		LOGINS.write(Logins::new(
			user_cred_map,
			Duration::from_secs(configs.login_timeout),
			configs.max_fails,
			used_challenges,
			configs.key_challenge_prefix,
			configs.salt_len
		));
		SESSIONS.write(Sessions::new(Duration::from_secs(configs.max_session_duration)));
		PIPES.write(Pipes::new(configs.suffix));
		SPECIALS.write(SpecialUsers::new(privileged));
	}

	// info!("Binding to {bind_addr} on {}", &configs.mount_point);

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
			.attach(Compression::fairing())
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
	};

	warn!("Exit Successful!");
	log_info!("Listener exited!");
}
