use async_std::sync::Mutex;
use rocket::http::Status;
use rocket::Request;
use rocket::request::{FromRequest, Outcome};
use std::ops::Deref;
use std::sync::Arc;

use crate::auth_state::Privilege;
use crate::SESSIONS;

pub struct AuthorizedUser;


#[async_trait]
impl<'r> FromRequest<'r> for AuthorizedUser {
	type Error = &'static str;

	async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		let mut iter = request.headers().get("Session-ID");
		let session_id = match iter.next() {
			Some(x) => String::from(x),
			None => return Outcome::Failure((Status::BadRequest, ()))
		};

		if unsafe { SESSIONS.is_valid_session(session_id) }.await {
			Outcome::Success(Self)
		} else {
			Outcome::Failure((Status::Unauthorized, "Missing Session-ID header"))
		}
	}
}


// pub struct CanCreateUser;
//
//
// #[async_trait]
// impl<'r> FromRequest<'r> for CanCreateUser {
// 	type Error = ();
//
// 	async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
// 		let mut iter = request.headers().get("Session-ID");
// 		let session = String::from(match iter.next() {
// 			Some(x) => x,
// 			None => return Outcome::Failure((Status::BadRequest, ()))
// 		});
//
// 		let username = AUTH_STATE.get_session_owner(&session).await;
// 		let privileges = AUTH_STATE.get_user_privileges(&username).await;
//
// 		if privileges.contains(&Privilege::CreateUser) {
// 			return Outcome::Success(CanCreateUser)
// 		}
// 		Outcome::Failure((Status::Unauthorized, ()))
// 	}
// }
