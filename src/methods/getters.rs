use std::collections::VecDeque;
use std::path::PathBuf;

use mangle_db_enums::{GatewayRequestHeader, GatewayResponseHeader};
use rocket::Either;
use rocket::http::{ContentType, CookieJar};
use simple_serde::{DeserializationErrorKind, PrimitiveSerializer};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use super::*;

#[rocket::get("/<root_path..>?<action>")]
pub(crate) async fn directory_tools(root_path: PathBuf, cookies: &CookieJar<'_>, globals: &GlobalState, action: String) -> (Status, Either<&'static str, (ContentType, Vec<u8>)>) {
	match action.as_str() {
		"list" => {
			let mut username = None;
			if let Some(session) = check_session_id!(globals.sessions, cookies, either) {
				username = globals.sessions.get_session_owner(&session).await;
				if username.is_none()  {
					error!("No session owner but session-id was valid!");
					return make_response!(BUG, either)
				}
			}

			let mut socket = take_pipe!(globals);

			let mut payload = vec![GatewayRequestHeader::ListDirectory.into()];

			payload.append(&mut root_path.to_str().unwrap().as_bytes().to_vec());

			write_socket!(socket, payload.as_slice(), either);

			let mut buffer: VecDeque<_> = read_socket!(socket, either).into();

			globals.pipes.return_pipe(socket).await;

			match parse_header!(buffer, either) {
				GatewayResponseHeader::Ok => {}
				GatewayResponseHeader::InternalError => return make_response!(BUG, either),
				GatewayResponseHeader::IsDirectoryError => return make_response!(BadRequest, Either::Left("The given path is not a directory")),
				_ => return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND))
			}

			let mut paths = String::new();

			loop {
				match buffer.deserialize_string() {
					Ok(path) => {
						let path_buf = root_path.join(path.clone());
						if !match &username {
							Some(username_str) => globals.permissions.can_user_read_here(username_str, &path_buf),
							None => globals.permissions.can_anonymous_read_here(&path_buf)
						} {
							continue
						}

						if !paths.is_empty() {
							paths += "\n";
						}
						paths += path.as_str();
					}
					Err(e) => match &e.kind {
						DeserializationErrorKind::UnexpectedEOF => break,
						_ => {
							default_error!(e, "parsing path from list");
							return make_response!(BUG, either)
						}
					}
				}
			}

			(Status::Ok, Either::Right((
				ContentType::Text,
				paths.as_bytes().to_vec()
			)))
		}
		_ => make_response!(BadRequest, Either::Left("Unrecognized action"))
	}
}

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

	let mut socket = take_pipe!(globals);

	let mut payload = vec![GatewayRequestHeader::BorrowResource.into()];
	payload.append(&mut path.to_str().unwrap().as_bytes().to_vec());

	write_socket!(socket, payload.as_slice(), either);

	let mut buffer: VecDeque<_> = read_socket!(socket, either).into();

	globals.pipes.return_pipe(socket).await;

	match parse_header!(buffer, either) {
		GatewayResponseHeader::Ok => {}
		GatewayResponseHeader::InternalError => return make_response!(BUG, either),
		_ => return make_response!(NotFound, Either::Left(RESOURCE_NOT_FOUND)),
	}

	let mime_type = match buffer.deserialize_string() {
		Ok(x) => x,
		Err(e) => {
			default_error!(e, "parsing mime type from db response");
			return make_response!(ServerError, Either::Left(BUG_MESSAGE))
		}
	};

	// let payload_size: u32 = match buffer.deserialize_num() {
	// 	Ok(x) => x,
	// 	Err(e) => {
	// 		default_error!(e, "parsing payload size from db response");
	// 		return make_response!(ServerError, Either::Left(BUG_MESSAGE))
	// 	}
	// };
	//
	// if buffer.len() != payload_size as usize {
	// 	error!("Payload size mismatch:\n\texpected: {}\n\tactual: {}", payload_size, buffer.len());
	// 	return make_response!(ServerError, Either::Left(BUG_MESSAGE))
	// }

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