use std::ops::Deref;
use std::sync::Arc;

use async_std::sync::Mutex;
use rocket::http::Status;
use rocket::Request;
use rocket::request::{FromRequest, Outcome};
use tokio::net::windows::named_pipe::NamedPipeClient;

use crate::AUTH_STATE;
use crate::auth_state::UserPrivileges;

pub struct MutexBiPipe(Arc<Mutex<NamedPipeClient>>);


impl Deref for MutexBiPipe {
	type Target = Mutex<NamedPipeClient>;

	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}


#[async_trait]
impl<'r> FromRequest<'r> for MutexBiPipe {
	type Error = ();

	async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		let mut iter = request.headers().get("Session-ID");
		let session = String::from(match iter.next() {
			Some(x) => x,
			None => return Outcome::Failure((Status::BadRequest, ()))
		});

		let roles = match AUTH_STATE.get_session_roles(&session).await {
			Some(x) => x,
			None => return Outcome::Failure((Status::Unauthorized, ()))
		};

		return match AUTH_STATE.get_bipipe(roles).await {
			Ok(x) => Outcome::Success(MutexBiPipe(x)),
			Err(e) => {
				log_default_error!(
					e,
					"creating bipipe"
				);
				Outcome::Failure((Status::InternalServerError, ()))
			}
		}
	}
}


pub struct CanCreateUser;


#[async_trait]
impl<'r> FromRequest<'r> for CanCreateUser {
	type Error = ();

	async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		let mut iter = request.headers().get("Session-ID");
		let session = String::from(match iter.next() {
			Some(x) => x,
			None => return Outcome::Failure((Status::BadRequest, ()))
		});

		let username = AUTH_STATE.get_session_owner(&session).await;
		let privileges = AUTH_STATE.get_user_privileges(&username).await;

		if privileges.contains(&UserPrivileges::CreateUser) {
			return Outcome::Success(CanCreateUser)
		}
		Outcome::Failure((Status::Unauthorized, ()))
	}
}
