use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Config as ArgonConfig, Error as ArgonError, hash_encoded};
use async_std::sync::{Mutex, RwLock, RwLockUpgradableReadGuard};
use ed25519_dalek::{PublicKey, Signature};
use mangle_db_enums::MANGLE_DB_SUFFIX;
use mangle_rust_utils::NestedMap;
use rand::{CryptoRng, Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;
use regex::Regex;
use tokio::spawn;
use tokio::time::sleep;

#[cfg(windows)]
use windows::*;

use crate::*;

declare_logger!(pub FAILED_LOGINS, File, 0, );


#[cfg(windows)]
mod windows {
	use std::pin::Pin;
	use std::task::{Context, Poll};

	use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
	use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

	use super::IOError;

	pub struct BiPipe(Pin<Box<NamedPipeClient>>);

	impl BiPipe {
		pub fn connect(to: &str) -> Result<Self, IOError> {
			ClientOptions::new()
				.open(r"\\.\pipe\".to_string() + to).map(|x| Self(Box::pin(x)))
		}
	}

	impl AsyncRead for BiPipe {
		fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
			self.0.as_mut().poll_read(cx, buf)
		}
	}

	impl AsyncWrite for BiPipe {
		fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IOError>> {
			self.0.as_mut().poll_write(cx, buf)
		}

		fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IOError>> {
			self.0.as_mut().poll_flush(cx)
		}

		fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IOError>> {
			self.0.as_mut().poll_shutdown(cx)
		}
	}
}

pub enum Credential {
	PasswordHash(String),
	Key(PublicKey),
}


struct FailedLoginAttempt {
	running_count: u8,
	time: Instant
}


pub enum LoginResult {
	Ok,
	/// Username does not exist
	NonexistentUser,
	/// The given credential challenge is not correct
	BadCredentialChallenge,
	/// The user cannot be authorized using the given credential challenge.
	/// ie. Giving a password when the user uses key based verification and vice-versa
	UnexpectedCredentials,
	/// The given credential challenge has been used before.
	/// Only returned on key based verification
	UsedChallenge,
	/// The given user cannot login right now as their account is being locked out
	LockedOut
}


#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Privilege {
	CreateUser
}


pub enum UserCreationError {
	UsernameInUse,
	BadPassword,
	ArgonError(ArgonError),
	BadUsername
}


#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionID([char; 32]);


pub struct SessionData {
	creation_time: Instant,
	owning_user: String
}


pub struct Logins {
	user_cred_map: RwLock<HashMap<String, Credential>>,
	lockout_time: Duration,
	max_fails: u8,
	failed_logins: RwLock<HashMap<String, FailedLoginAttempt>>,
	used_challenges: Mutex<HashSet<String>>,
	key_challenge_prefix: String,
	argon2_config: ArgonConfig<'static>,
	salt_len: u8,
	min_username_len: u8,
	max_username_len: u8,
	password_regex: Option<Regex>
}


pub struct SpecialUsers {
	privileged: HashMap<String, HashSet<Privilege>>
}


pub struct Sessions {
	user_session_map: RwLock<HashMap<String, Arc<SessionID>>>,
	session_user_map: RwLock<HashMap<Arc<SessionID>, String>>,
	sessions: RwLock<HashMap<SessionID, SessionData>>,
	pub(crate) max_session_duration: Duration
}


pub struct Pipes {
	free_pipes: Mutex<Vec<BiPipe>>,
	local_bind_addr: String
}


pub struct Permissions {
	public_read_paths: NestedMap<String, ()>,
	user_read_paths: HashMap<String, NestedMap<String, ()>>,
	user_write_paths: HashMap<String, NestedMap<String, ()>>,
	all_user_home_read_paths: NestedMap<String, ()>,
	all_user_home_write_paths: NestedMap<String, ()>,
	all_user_extern_read_paths: NestedMap<String, ()>,
	all_user_extern_write_paths: NestedMap<String, ()>,
	user_home_parent: Vec<String>,
	user_home_parent_segment_count: usize,
}


impl From<ArgonError> for UserCreationError {
	fn from(e: ArgonError) -> Self {
		Self::ArgonError(e)
	}
}


impl Logins {
	pub fn new(
		user_cred_map: HashMap<String, Credential>,
		lockout_time: Duration,
		max_fails: u8,
		used_challenges: HashSet<String>,
		key_challenge_prefix: String,
		salt_len: u8,
		min_username_len: u8,
		max_username_len: u8,
		cleanup_delay: u32,
		password_regex: Option<Regex>
	) -> Arc<Self> {
		if max_username_len < min_username_len {
			panic!("max_username_len is smaller than min_username_len!")
		}

		let out = Arc::new(Self {
			user_cred_map: RwLock::new(user_cred_map),
			lockout_time,
			max_fails,
			used_challenges: Mutex::new(used_challenges),
			failed_logins: Default::default(),
			key_challenge_prefix,
			argon2_config: ArgonConfig::default(),
			salt_len,
			min_username_len,
			max_username_len,
			password_regex
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_expired().await;
			}
		});

		out
	}

	pub async fn prune_expired(&self) {
		let mut writer = self.failed_logins.write().await;
		let old_fails = replace(writer.deref_mut(), HashMap::new());
		for (username, fail) in old_fails {
			if fail.time.elapsed() < self.lockout_time {
				writer.insert(username, fail);
			}
		}
	}

	pub async fn add_user(&self, username: String, password: String) -> Result<(), UserCreationError> {
		if username.len() < self.min_username_len as usize || username.len() > self.max_username_len as usize || !username.chars().all(char::is_alphanumeric) {
			return Err(UserCreationError::BadUsername)
		}
		if let Some(re) = &self.password_regex {
			if !re.is_match(password.as_str()) {
				return Err(UserCreationError::BadPassword)
			}
		}
		let reader = self.user_cred_map.upgradable_read().await;
		if reader.contains_key(&username) {
			return Err(UserCreationError::UsernameInUse)
		}
		let mut writer = RwLockUpgradableReadGuard::upgrade(reader).await;

		writer.insert(username, Credential::PasswordHash(
			hash_encoded(
				password.as_bytes(),
				thread_rng()
					.sample_iter(&Alphanumeric)
					.take(self.salt_len as usize)
					.collect::<Vec<_>>()
					.as_slice(),
				&self.argon2_config
			)?
		));

		Ok(())
	}

	pub async fn try_login_password(&self, username: &String, password: String) -> LoginResult {
		{
			let reader = self.failed_logins.read().await;

			if let Some(x) = reader.get(username) {
				if x.running_count >= self.max_fails {
					if x.time.elapsed() < self.lockout_time {
						return LoginResult::LockedOut
					} else {
						drop(reader);
						let mut writer = self.failed_logins.write().await;
						writer.remove(username);
					}
				}
			}
		}

		let reader = self.user_cred_map.read().await;

		match reader.get(username) {
			Some(Credential::PasswordHash(hash)) =>
				if argon2::verify_encoded(hash, password.as_bytes()).unwrap() {
					let reader = self.failed_logins.read().await;

					if reader.contains_key(username) {
						drop(reader);
						self.failed_logins.write().await.remove(username);
					}

					LoginResult::Ok
				} else {
					let mut writer = self.failed_logins.write().await;

					if let Some(fail) = writer.get_mut(username) {
						fail.running_count += 1;
						fail.time = Instant::now();
						if fail.running_count == self.max_fails {
							FAILED_LOGINS.warn(format!("{} failed to login too many times", username)).await
						}
					} else {
						writer.insert(username.clone(), FailedLoginAttempt {
							running_count: 1,
							time: Instant::now()
						});
					}

					LoginResult::BadCredentialChallenge
				},
			Some(Credential::Key(_)) => LoginResult::UnexpectedCredentials,
			None => LoginResult::NonexistentUser
		}
	}

	pub async fn try_login_key(&self, username: &String, challenge: String, signature: Signature) -> LoginResult {
		let reader = self.user_cred_map.read().await;

		match reader.get(username) {
			Some(Credential::PasswordHash(_)) => LoginResult::UnexpectedCredentials,
			Some(Credential::Key(key)) => {
				if !challenge.starts_with(&self.key_challenge_prefix) {
					return LoginResult::BadCredentialChallenge
				}

				let mut used_challenges = self.used_challenges.lock().await;
				if used_challenges.contains(&challenge) {
					LoginResult::UsedChallenge
				} else if key.verify_strict(challenge.as_bytes(), &signature).is_ok() {
					used_challenges.insert(challenge);
					LoginResult::Ok
				} else {
					LoginResult::BadCredentialChallenge
				}
			}
			None => LoginResult::NonexistentUser
		}
	}
}


impl SpecialUsers {
	pub fn new(privileged: HashMap<String, HashSet<Privilege>>) -> Self {
		Self {
			privileged
		}
	}
	pub fn can_user_create_user(&self, username: &String) -> bool {
		if let Some(privileges) = self.privileged.get(username) {
			privileges.contains(&Privilege::CreateUser)
		} else {
			false
		}
	}
}


impl SessionID {
	pub fn new<T: CryptoRng + RngCore>(rand_gen: &mut T) -> Self {
		let mut arr = [char::default(); 32];

		rand_gen
			.sample_iter(&Alphanumeric)
			.take(32)
			.enumerate()
			.for_each(
				|(i, c)| { arr[i] = char::from(c) }
			);

		Self(arr)
	}
}


impl ToString for SessionID {
	fn to_string(&self) -> String {
		self.0.iter().cloned().collect()
	}
}


impl TryFrom<String> for SessionID {
	type Error = String;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Ok(Self(value.to_string().chars().collect::<Vec<_>>().try_into().map_err(|_| value)?))
	}
}


impl Sessions {
	pub fn new(max_session_duration: Duration, cleanup_delay: u32) -> Arc<Self> {
		let out = Arc::new(Self {
			user_session_map: Default::default(),
			session_user_map: Default::default(),
			sessions: Default::default(),
			max_session_duration
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_expired().await;
			}
		});

		out
	}
	pub async fn create_session(&self, username: String) -> SessionID {
		if let Some(x) = self.user_session_map.read().await.get(&username) {
			return x.deref().clone()
		}

		let mut writer = self.sessions.write().await;
		let mut session_id;

		{
			let mut rand_gen = thread_rng();
			session_id = SessionID::new(&mut rand_gen);

			while writer.contains_key(&session_id) {
				session_id = SessionID::new(&mut rand_gen)
			}
		}

		writer.insert(session_id.clone(), SessionData {
			creation_time: Instant::now(),
			owning_user: username.clone()
		});
		drop(writer);

		let arc_session_id = Arc::new(session_id.clone());
		self.user_session_map.write().await.insert(username.clone(), arc_session_id.clone());
		self.session_user_map.write().await.insert(arc_session_id, username);

		session_id
	}

	pub async fn prune_expired(&self) {
		let mut session_writer = self.sessions.write().await;
		let old_sessions = replace(session_writer.deref_mut(), HashMap::new());
		let mut user_session_writer = self.user_session_map.write().await;
		let mut session_user_writer = self.session_user_map.write().await;

		for (session_id, session_data) in old_sessions {
			if session_data.creation_time.elapsed() > self.max_session_duration {
				user_session_writer.remove(&session_data.owning_user);
				session_user_writer.remove(&session_id);
			} else {
				session_writer.insert(session_id, session_data);
			}
		}
	}

	pub async fn is_valid_session(&self, session_id: &SessionID) -> bool {
		self.sessions.read().await.contains_key(session_id)
	}

	pub async fn get_session_owner(&self, session_id: &SessionID) -> Option<String> {
		self.session_user_map.read().await.get(session_id).cloned()
	}
}


impl Pipes {
	pub fn new(local_bind_addr: String, cleanup_delay: u32) -> Arc<Self> {
		let out = Arc::new(Self {
			free_pipes: Default::default(),
			local_bind_addr: String::from(MANGLE_DB_SUFFIX) + local_bind_addr.as_str()
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_pipes().await;
			}
		});

		out
	}
	pub async fn take_pipe(&self) -> Result<BiPipe, IOError> {
		if let Some(x) = self.free_pipes.lock().await.pop() {
			Ok(x)
		} else {
			BiPipe::connect(self.local_bind_addr.as_str())
		}
	}

	pub async fn return_pipe(&self, pipe: BiPipe) {
		self.free_pipes.lock().await.push(pipe);
	}

	pub async fn prune_pipes(&self) {
		self.free_pipes.lock().await.clear();
	}
}


impl Permissions {
	pub fn new(
		public_read_paths: NestedMap<String, ()>,
		all_user_home_read_paths: NestedMap<String, ()>,
		all_user_home_write_paths: NestedMap<String, ()>,
		all_user_extern_read_paths: NestedMap<String, ()>,
		all_user_extern_write_paths: NestedMap<String, ()>,
		user_home_parent: Vec<String>,
		user_read_paths: HashMap<String, NestedMap<String, ()>>,
		user_write_paths: HashMap<String, NestedMap<String, ()>>,
	) -> Self {
		Self {
			public_read_paths,
			user_read_paths,
			user_write_paths,
			all_user_home_read_paths,
			all_user_home_write_paths,
			all_user_extern_read_paths,
			all_user_extern_write_paths,
			user_home_parent_segment_count: user_home_parent.len(),
			user_home_parent,
		}
	}

	pub fn can_anonymous_read_here(&self, path: &PathBuf) -> bool {
		self.public_read_paths.partial_contains(path_buf_to_segments(path))
	}

	pub fn can_user_write_here(&self, username: &String, path: &PathBuf) -> bool {
		let mut segments = path_buf_to_segments(path);

		if segments.starts_with(self.user_home_parent.as_slice()) {
			if let Some(user_path) = segments.get(self.user_home_parent_segment_count) {
				if user_path != username {
					return false
				}
				segments.drain(0..(self.user_home_parent_segment_count + 1));
				self.all_user_home_write_paths.partial_contains(segments)
			} else {
				false
			}
		} else if self.all_user_extern_write_paths.partial_contains(segments.clone()) {
			return true
		} else {
			match self.user_write_paths.get(username) {
				None => false,
				Some(x) => x.partial_contains(segments)
			}
		}
	}

	pub fn can_user_read_here(&self, username: &String, path: &PathBuf) -> bool {
		let mut segments = path_buf_to_segments(path);

		if self.public_read_paths.partial_contains(segments.iter()) {
			return true
		}

		if segments.starts_with(self.user_home_parent.as_slice()) {
			if let Some(user_path) = segments.get(self.user_home_parent_segment_count) {
				if user_path != username {
					return false
				}
				segments.drain(0..(self.user_home_parent_segment_count + 1));
				self.all_user_home_read_paths.partial_contains(segments)
			} else {
				false
			}
		} else if self.all_user_extern_read_paths.partial_contains(segments.clone()) {
			return true
		} else {
			match self.user_read_paths.get(username) {
				None => false,
				Some(x) => x.partial_contains(segments)
			}
		}
	}
}
