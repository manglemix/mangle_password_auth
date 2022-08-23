use std::sync::Arc;

use rocket::http::Status;
use rocket::State;

use crate::singletons::{Logins, Permissions, Pipes, Sessions, SpecialUsers};

pub(super) mod auth;
pub(super) mod getters;
pub(super) mod setters;


const BUG_MESSAGE: &str = "We encountered a bug on our end. Please try again later";
const DB_CONNECTION: &str = "We had difficulties connecting to our database. Please try again later";
const SESSION_COOKIE_NAME: &str = "Session-ID";
const MANGLE_DB_CLOSED: &str = "MangleDB has closed the connection";
const RESOURCE_NOT_FOUND: &str = "Resource not found, or you do not have adequate permissions";


macro_rules! write_socket {
    ($socket: expr, $payload: expr) => {
		write_socket!($socket, $payload, $crate::methods::DB_CONNECTION)
	};
    ($socket: expr, $payload: expr, either) => {
		write_socket!($socket, $payload, rocket::Either::Left(DB_CONNECTION))
	};
    ($socket: expr, $payload: expr, $server_err_msg: expr) => {
		match $socket.write_all($payload.to_bytes().as_slice()).await {
			Ok(_) => {}
			Err(e) => {
				use $crate::*;
				default_error!(e, "writing to socket");
				return make_response!(ServerError, $server_err_msg);
			}
		}
	};
}
macro_rules! read_socket {
	($socket: expr) => {
		read_socket!($socket, $crate::methods::DB_CONNECTION, $crate::methods::BUG_MESSAGE)
	};
	($socket: expr, either) => {
		read_socket!($socket, rocket::Either::Left($crate::methods::DB_CONNECTION), rocket::Either::Left($crate::methods::BUG_MESSAGE))
	};
    ($socket: expr, $conn_err_msg: expr, $header_err_msg: expr) => {{
		let mut header_and_size = [0; 5];

		match $socket.read_exact(header_and_size.as_mut_slice()).await {
			Ok(0) => {
				use crate::*;
				error!("{}", $crate::methods::MANGLE_DB_CLOSED);
				return make_response!(ServerError, $conn_err_msg)
			}
			Ok(_) => {}
			Err(e) => {
				default_error!(e, "listening to stream");
				return make_response!(ServerError, $conn_err_msg)
			}
		}

		let body_size = u32::from_be_bytes([header_and_size[0], header_and_size[1], header_and_size[2], header_and_size[3]]);
		let mut data = vec![0; body_size as usize];

		if body_size > 0 {
			match $socket.read_exact(data.as_mut_slice()).await {
				Ok(0) => {
					use crate::*;
					error!("{}", $crate::methods::MANGLE_DB_CLOSED);
					return make_response!(ServerError, $conn_err_msg)
				}
				Ok(_) => {}
				Err(e) => {
					default_error!(e, "listening to stream");
					return make_response!(ServerError, $conn_err_msg)
				}
			}
			match mangle_db_enums::Message::new_response(header_and_size[0], data) {
				Ok(x) => x,
				Err(_) => {
					error!("unrecognized_header: {}", header_and_size[0]);
					return make_response!(ServerError, $header_err_msg)
				}
			}
		} else {
			match mangle_db_enums::Message::new_response_header(header_and_size[0]) {
				Ok(x) => x,
				Err(_) => {
					error!("unrecognized_header: {}", header_and_size[0]);
					return make_response!(ServerError, $header_err_msg)
				}
			}
		}
	}};
}
macro_rules! make_response {
	(ServerError, $reason: expr) => {
		make_response!(rocket::http::Status::InternalServerError, $reason)
	};
	(NotFound, $reason: expr) => {
		make_response!(rocket::http::Status::NotFound, $reason)
	};
	(BadRequest, $reason: expr) => {
		make_response!(rocket::http::Status::BadRequest, $reason)
	};
	(Ok, $reason: expr) => {
		make_response!(rocket::http::Status::Ok, $reason)
	};
	(BUG) => {
		make_response!(NotFound, $crate::methods::BUG_MESSAGE)
	};
	(BUG, either) => {
		make_response!(NotFound, rocket::Either::Left($crate::methods::BUG_MESSAGE))
	};
    ($code: expr, $reason: expr) => {
		($code, $reason)
	};
}
// macro_rules! parse_header {
//     ($buffer: expr) => {
// 		parse_header!($buffer, $crate::methods::BUG_MESSAGE)
// 	};
//     ($buffer: expr, either) => {
// 		parse_header!($buffer, rocket::Either::Left(BUG_MESSAGE))
// 	};
//     ($buffer: expr, $err_msg: expr) => {{
// 		let header = match $buffer.remove(0) {
// 			Some(x) => x,
// 			None => {
// 				use $crate::*;
// 				error!("Empty response from db");
// 				return make_response!(ServerError, $err_msg);
// 			}
// 		};
// 		match TryInto::<GatewayResponseHeader>::try_into(header) {
// 			Ok(x) => x,
// 			Err(_) => {
// 				use $crate::*;
// 				error!("Unrecognised header {header}");
// 				return make_response!(ServerError, $err_msg);
// 			}
// 		}
// 	}};
// }
macro_rules! check_session_id {
    ($session: expr, $cookies: expr) => {
		check_session_id!($session, $cookies, "The Session-ID is malformed", "The Session-ID is invalid or expired")
	};
    ($session: expr, $cookies: expr, either) => {
		check_session_id!($session, $cookies, rocket::Either::Left("The Session-ID is malformed"), rocket::Either::Left("The Session-ID is invalid or expired"))
	};
    ($session: expr, $cookies: expr, $err_msg1: expr, $err_msg2: expr) => {
		if let Some(cookie) = $cookies.get(SESSION_COOKIE_NAME) {
			let session_id = match $crate::singletons::SessionID::try_from(cookie.value().to_string()) {
				Ok(x) => x,
				Err(_) => return make_response!(BadRequest, $err_msg1)
			};
			if !$session.is_valid_session(&session_id).await {
				return make_response!(rocket::http::Status::Unauthorized, $err_msg2)
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
		return make_response!(BadRequest, rocket::Either::Left("Missing Session-ID cookie"))
	};
}
macro_rules! take_pipe {
    ($globals: expr) => {
		match $globals.pipes.take_pipe().await {
			Ok(x) => x,
			Err(e) => {
				default_error!(e, "connecting to db");
				return make_response!(ServerError, DB_CONNECTION)
			}
		}
	};
    ($globals: expr, either) => {
		match $globals.pipes.take_pipe().await {
			Ok(x) => x,
			Err(e) => {
				default_error!(e, "connecting to db");
				return make_response!(ServerError, Either::Left(DB_CONNECTION))
			}
		}
	};
}

use check_session_id;
use make_response;
use missing_session;
// use parse_header;
use read_socket;
use write_socket;
use take_pipe;

type Response = (Status, &'static str);


pub(super) struct _GlobalState {
	pub(super) logins: Arc<Logins>,
	pub(super) sessions: Arc<Sessions>,
	pub(super) pipes: Arc<Pipes>,
	pub(super) special_users: SpecialUsers,
	pub(super) permissions: Permissions
}


type GlobalState = State<_GlobalState>;