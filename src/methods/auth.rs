use std::ops::Add;
use std::time::SystemTime;

use rocket::http::{Cookie, CookieJar};
use rocket::time::OffsetDateTime;

use crate::methods::GlobalState;
use crate::singletons::{LoginResult, UserCreationError};

use super::*;

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

	match globals.logins.add_user(username, password) {
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