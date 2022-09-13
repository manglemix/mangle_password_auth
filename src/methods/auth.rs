use std::collections::VecDeque;
/// Methods that involve user authentication
///
/// These do not interact with the database
use std::ops::Add;
use std::time::SystemTime;
use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader, Message};

use rocket::http::{Cookie, CookieJar};
use rocket::time::OffsetDateTime;
use simple_serde::PrimitiveSerializer;

use crate::methods::GlobalState;
use crate::singletons::{LoginResult, UserCreationError};

use super::*;

/// Try to start a session with a username and password
///
/// If the user has already opened one and it has not expired, it will be returned
#[rocket::get("/users_with_password?<username>&<password>")]
pub(crate) async fn get_session_with_password(username: String, password: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	match globals.logins.try_login_password(&username, password) {
		LoginResult::Ok => {
			let session_id = globals.sessions.create_session(username);
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


/// Try to start a session with a username and signature
///
/// If the user has already opened one and it has not expired, it will be returned
#[rocket::get("/users_with_key?<username>&<message>&<signature>")]
pub(crate) async fn get_session_with_key(username: String, message: String, signature: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	let signature = match signature.parse() {
		Ok(x) => x,
		Err(_) => return make_response!(BadRequest, "Invalid signature")
	};
	match globals.logins.try_login_key(&username, message, signature) {
		LoginResult::Ok => {
			let session_id = globals.sessions.create_session(username);
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


/// Tries to create a new user, granted the creating user has appropriate abilities
#[rocket::put("/create_user_with_password?<username>&<password>")]
pub(crate) async fn make_user(username: String, password: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	let session_id = match check_session_id!(globals.sessions, cookies) {
		Some(x) => x,
		None => missing_session!()
	};

	match globals.sessions.get_session_owner(&session_id) {
		Some(creator) => if !globals.special_users.can_user_create_user(&creator) {
			return make_response!(Status::Unauthorized, "You are not authorized to create users")
		}
		None => {
			error!("Session-ID was valid but not associated with a user!");
			return make_response!(BUG)
		}
	}

	match globals.logins.add_user(username.clone(), password) {
		Ok(()) => {}
		Err(e) => return match e {
			UserCreationError::ArgonError(e) => {
				default_error!(e, "generating password hash");
				make_response!(BUG)
			},
			UserCreationError::UsernameInUse => make_response!(BadRequest, "Username already in use"),
			UserCreationError::BadPassword => make_response!(BadRequest, "Password is not strong enough"),
			UserCreationError::BadUsername => make_response!(BadRequest, "Username is not alphanumeric or too short or too long")
		}
	}

	let mut pipe = take_pipe!(globals);
	let mut data = VecDeque::new();

	data.serialize_string(globals.logins.user_home_template_path.to_str().unwrap());
	data.serialize_string(username.clone());

	write_socket!(
		pipe,
		Message::new_request(
			GatewayRequestHeader::DuplicateDirectory,
			data
		).unwrap()
	);

	let response = read_socket!(pipe);
	globals.pipes.return_pipe(pipe);

	match response.header {
		GatewayResponseHeader::Ok => make_response!(Ok, "User created successfully"),
		GatewayResponseHeader::BadPath => {
			error!("Received BadPath error with duplicate_directory");
			globals.logins.delete_user(&username);
			make_response!(BUG)
		}
		GatewayResponseHeader::BadRequest => {
			error!("Received BadRequest even though username does not exist: {}", username);
			globals.logins.delete_user(&username);
			make_response!(BUG)
		}
		_ => unreachable!()
	}
}


/// Tries to delete the user that is currently logged in
#[rocket::delete("/delete_my_account")]
pub(crate) async fn delete_user(cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
	let session_id = match check_session_id!(globals.sessions, cookies) {
		Some(x) => x,
		None => missing_session!()
	};

	let username = match globals.sessions.get_session_owner(&session_id) {
		Some(username) => username,
		None => {
			error!("Session-ID was valid but not associated with a user!");
			return make_response!(BUG)
		}
	};

	if !globals.logins.delete_user(&username) {
		return make_response!(BadRequest, "User does not exist")
	}

	let mut pipe = take_pipe!(globals);
	let mut data = VecDeque::new();

	data.serialize_string(globals.logins.user_home_template_path.join(username.clone()).to_str().unwrap());

	write_socket!(
		pipe,
		Message::new_request(
			GatewayRequestHeader::DeleteDirectory,
			data
		).unwrap()
	);

	let response = read_socket!(pipe);
	globals.pipes.return_pipe(pipe);

	match response.header {
		GatewayResponseHeader::Ok => make_response!(Ok, "User deleted successfully"),
		GatewayResponseHeader::BadPath => {
			error!("Received BadPath error with duplicate_directory");
			make_response!(BUG)
		}
		GatewayResponseHeader::BadRequest => {
			error!("Received BadRequest even though username does exist: {}", username);
			make_response!(BUG)
		}
		_ => unreachable!()
	}
}