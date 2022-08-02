use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::ops::{DerefMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Config as ArgonConfig, Error as ArgonError, hash_encoded};
use async_std::sync::{Mutex, RwLock, RwLockUpgradableReadGuard};
use ed25519_dalek::{PublicKey, Signature};
use mangle_db_enums::MANGLE_DB_SUFFIX;
use rand::{CryptoRng, Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;

use crate::*;
use crate::mangle_rust_utils::Colorize;

type ArcString = Arc<String>;


#[cfg(windows)]
mod windows {
	use std::pin::Pin;
	use std::task::{Context, Poll};
	use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
	use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
	use super::IOError;

	pub struct BiPipe(NamedPipeClient);

	impl BiPipe {
		pub fn connect(to: &str) -> Result<Self, IOError> {
			ClientOptions::new()
				.open(r"\\.\pipe\".to_string() + to).map(|x| Self(x))
		}
	}

	impl AsyncRead for BiPipe {
		fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
			Pin::new(&mut self.0).poll_read(cx, buf)
		}
	}

	impl AsyncWrite for BiPipe {
		fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IOError>> {
			Pin::new(&mut self.0).poll_write(cx, buf)
		}

		fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IOError>> {
			Pin::new(&mut self.0).poll_flush(cx)
		}

		fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IOError>> {
			Pin::new(&mut self.0).poll_shutdown(cx)
		}
	}
}
#[cfg(windows)]
use windows::*;


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
	ArgonError(ArgonError)
}


#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionID([char; 32]);


pub struct SessionData {
	creation_time: Instant,
	owning_user: ArcString
}


pub struct Logins<'a> {
	user_cred_map: RwLock<HashMap<ArcString, Credential>>,
	lockout_time: Duration,
	max_fails: u8,
	failed_logins: RwLock<HashMap<ArcString, FailedLoginAttempt>>,
	used_challenges: Mutex<HashSet<String>>,
	key_challenge_prefix: String,
	argon2_config: ArgonConfig<'a>,
	salt_len: u8
}


pub struct SpecialUsers {
	privileged: HashMap<ArcString, HashSet<Privilege>>
}


pub struct Sessions {
	user_session_map: RwLock<HashMap<ArcString, Arc<SessionID>>>,
	session_user_map: RwLock<HashMap<Arc<SessionID>, ArcString>>,
	sessions: RwLock<HashMap<SessionID, SessionData>>,
	pub(crate) max_session_duration: Duration
}


pub struct Pipes {
	free_pipes: Mutex<Vec<BiPipe>>,
	local_bind_addr: String
}


impl From<ArgonError> for UserCreationError {
	fn from(e: ArgonError) -> Self {
		Self::ArgonError(e)
	}
}


impl<'a> Logins<'a> {
	pub fn new(
		user_cred_map: HashMap<ArcString, Credential>,
		lockout_time: Duration,
		max_fails: u8,
		used_challenges: HashSet<String>,
		key_challenge_prefix: String,
		salt_len: u8
	) -> Self {
		Self {
			user_cred_map: RwLock::new(user_cred_map),
			lockout_time,
			max_fails,
			used_challenges: Mutex::new(used_challenges),
			failed_logins: Default::default(),
			key_challenge_prefix,
			argon2_config: ArgonConfig::default(),
			salt_len
		}
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
		let reader = self.user_cred_map.upgradable_read().await;
		if reader.contains_key(&username) {
			return Err(UserCreationError::UsernameInUse)
		}
		let mut writer = RwLockUpgradableReadGuard::upgrade(reader).await;

		writer.insert(Arc::new(username), Credential::PasswordHash(
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
						// TODO Log brute force
					} else {
						writer.insert(Arc::new(username.clone()), FailedLoginAttempt {
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
	pub fn new(privileged: HashMap<ArcString, HashSet<Privilege>>) -> Self {
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
	pub fn new(max_session_duration: Duration) -> Self {
		Self {
			user_session_map: Default::default(),
			session_user_map: Default::default(),
			sessions: Default::default(),
			max_session_duration
		}
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

		let username = Arc::new(username);
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

	pub async fn get_session_owner(&self, session_id: &SessionID) -> Option<ArcString> {
		self.session_user_map.read().await.get(session_id).cloned()
	}
}


impl Pipes {
	pub fn new(local_bind_addr: String) -> Self {
		Self {
			free_pipes: Default::default(),
			local_bind_addr: String::from(MANGLE_DB_SUFFIX) + local_bind_addr.as_str()
		}
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
