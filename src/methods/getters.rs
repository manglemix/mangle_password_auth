use std::collections::VecDeque;
use std::path::PathBuf;

use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader};
use rocket::Either;
use rocket::http::{ContentType, CookieJar};
use simple_serde::PrimitiveSerializer;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::*;

#[rocket::get("/<path..>")]
pub(crate) async fn borrow_resource(path: PathBuf, cookies: &CookieJar<'_>, globals: &GlobalState) -> (Status, Either<&'static str, (ContentType, Vec<u8>)>) {
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