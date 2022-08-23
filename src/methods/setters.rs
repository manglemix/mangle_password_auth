use std::collections::VecDeque;
use std::path::PathBuf;

use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader, Message};
use rocket::Either;
use rocket::http::{ContentType, CookieJar};
use simple_serde::PrimitiveSerializer;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::*;

#[rocket::put("/<path..>", data = "<data>")]
pub(crate) async fn put_resource(path: PathBuf, data: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
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

	let mut socket = take_pipe!(globals);

	let path = path.to_str().unwrap();
	let mut payload = VecDeque::with_capacity(8 + path.len() + data.len());
	payload.serialize_string(path);
	payload.serialize_string(data);

	write_socket!(
		socket,
		Message::new_request(
			GatewayRequestHeader::CustomCommand,
			payload
		).unwrap()
	);

	let message = read_socket!(socket);

	globals.pipes.return_pipe(socket).await;

	match message.header {
		GatewayResponseHeader::Ok => make_response!(Ok, "Resource put successfully"),
		GatewayResponseHeader::InternalError => make_response!(BUG),
		GatewayResponseHeader::NotFound => make_response!(NotFound, RESOURCE_NOT_FOUND),
		GatewayResponseHeader::BadResource => make_response!(BadRequest, "The given resource is not valid"),
		_ => unreachable!()
	}
}


#[rocket::post("/<path..>", data = "<data>")]
pub(crate) async fn post_data(path: PathBuf, data: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> (Status, Either<&'static str, (ContentType, Vec<u8>)>) {
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

	let path = path.to_str().unwrap();
	let mut payload = VecDeque::with_capacity(8 + path.len() + data.len());
	payload.serialize_string(path);
	payload.serialize_string(data);

	write_socket!(
		socket,
		Message::new_request(
			GatewayRequestHeader::CustomCommand,
			payload
		).unwrap(),
		either
	);

	let message = read_socket!(socket, either);

	globals.pipes.return_pipe(socket).await;

	match message.header {
		GatewayResponseHeader::Ok => {}
		GatewayResponseHeader::InternalError => return make_response!(BUG, either),
		_ => return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND)),
	}

	let mut buffer = message.body.unwrap_or_default();

	let mime_type = match buffer.deserialize_string() {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "parsing mime type from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

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