use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Config as ArgonConfig, Error as ArgonError, hash_encoded};
use ed25519_dalek::{PublicKey, Signature};
use mangle_db_enums::MANGLE_DB_SUFFIX;
use mangle_rust_utils::NestedMap;
use rand::{CryptoRng, Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;
use regex::Regex;
use tokio::spawn;
use tokio::time::sleep;
use std::sync::{Mutex, RwLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeClient as LocalPipe};
// use windows::LocalPipe;


use crate::*;

declare_logger!([pub] FAILED_LOGINS);

/// The public component of a user credential
///
/// For passwords, it's their hash
/// For keys, its the public key
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


/// Special abilities that a user can have
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Privilege {
	CreateUser
}


pub enum UserCreationError {
	UsernameInUse,
	/// Username does not pass the password regex
	BadPassword,
	/// Error using argon hashing (pretty rare)
	ArgonError(ArgonError),
	/// Username is not alphanumeric
	BadUsername
}


/// Identification of a session
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionID([char; 32]);


pub struct SessionData {
	/// Time that the session was created
	creation_time: Instant,
	/// Username of user that created it
	owning_user: String
}


/// Manages user authentication and user creation
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
	password_regex: Regex,
	pub(crate) user_home_template_path: PathBuf
}


/// Tracks users that have special abilities
///
/// Once the server has started up, no new users can have special abilities
pub struct SpecialUsers {
	privileged: HashMap<String, HashSet<Privilege>>
}


/// Manages user sessions
pub struct Sessions {
	user_session_map: RwLock<HashMap<String, Arc<SessionID>>>,
	session_user_map: RwLock<HashMap<Arc<SessionID>, String>>,
	sessions: RwLock<HashMap<Arc<SessionID>, SessionData>>,
	pub(crate) max_session_duration: Duration
}


/// A pipe that can either be local or remote
pub enum EitherPipe {
	Local(Pin<Box<LocalPipe>>),
	Remote(Pin<Box<TcpStream>>)
}


impl EitherPipe {
	/// Connect to the database through a local pipe
	///
	/// Named Pipe on windows, Unix socket on linux
	fn connect_local(to: &str) -> Result<Self, IOError> {
		#[cfg(windows)]
		tokio::net::windows::named_pipe::ClientOptions::new()
			.open(r"\\.\pipe\".to_string() + to).map(|x| Self::Local(Box::pin(x)))
	}
	/// Connect to the database through a TCP socket
	async fn connect_remote(to: &str) -> Result<Self, IOError> {
		TcpStream::connect(to).await.map(|x| EitherPipe::Remote(Box::pin(x)))
	}
}


impl AsyncRead for EitherPipe {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		match self.get_mut() {
			EitherPipe::Local(x) => x.as_mut().poll_read(cx, buf),
			EitherPipe::Remote(x) => x.as_mut().poll_read(cx, buf)
		}
	}
}


impl AsyncWrite for EitherPipe {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IOError>> {
		match self.get_mut() {
			EitherPipe::Local(x) => x.as_mut().poll_write(cx, buf),
			EitherPipe::Remote(x) => x.as_mut().poll_write(cx, buf)
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IOError>> {
		match self.get_mut() {
			EitherPipe::Local(x) => x.as_mut().poll_flush(cx),
			EitherPipe::Remote(x) => x.as_mut().poll_flush(cx)
		}
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IOError>> {
		match self.get_mut() {
			EitherPipe::Local(x) => x.as_mut().poll_shutdown(cx),
			EitherPipe::Remote(x) => x.as_mut().poll_shutdown(cx)
		}
	}
}


/// Manages pipes to the database
pub struct Pipes {
	free_pipes: Mutex<Vec<EitherPipe>>,
	bind_addr: String,
	is_local: bool
}


/// Tracks database read write permissions
///
/// Permissions are immutable once the server has started up
pub struct Permissions {
	/// Paths that anonymous users can read
	public_read_paths: NestedMap<String, ()>,
	/// Paths that specific users can read at
	user_read_paths: HashMap<String, NestedMap<String, ()>>,
	/// Paths that specific users can write at
	user_write_paths: HashMap<String, NestedMap<String, ()>>,
	/// Paths that all users can read at that are under their home path
	all_user_home_read_paths: NestedMap<String, ()>,
	/// Paths that all users can write at that are under their home path
	all_user_home_write_paths: NestedMap<String, ()>,
	/// Paths that all users can read at that are not in their home
	all_user_extern_read_paths: NestedMap<String, ()>,
	/// Paths that all users can write at that are not in their home
	all_user_extern_write_paths: NestedMap<String, ()>,
	/// The parent directory to all user home directories.
	/// Each element is a name of a directory
	user_home_parent: Vec<String>,
	/// The length of user_home_parent
	user_home_parent_segment_count: usize,
}


impl From<ArgonError> for UserCreationError {
	fn from(e: ArgonError) -> Self {
		Self::ArgonError(e)
	}
}


impl Logins {
	/// Creates a Logins instance that has a separate task that performs occasional cleanups
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
		password_regex: Regex,
		user_home_template_path: PathBuf
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
			password_regex,
			user_home_template_path
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_expired();
			}
		});

		out
	}

	/// Remove failed login attempts that are expired
	fn prune_expired(&self) {
		let mut writer = self.failed_logins.write().unwrap();
		let old_fails = replace(writer.deref_mut(), HashMap::new());
		for (username, fail) in old_fails {
			if fail.time.elapsed() < self.lockout_time {
				writer.insert(username, fail);
			}
		}
	}

	/// Create a new user
	///
	/// New users can only be made with a password, not a key
	pub fn add_user(&self, username: String, password: String) -> Result<(), UserCreationError> {
		if username.len() < self.min_username_len as usize || username.len() > self.max_username_len as usize || !username.chars().all(char::is_alphanumeric) {
			return Err(UserCreationError::BadUsername)
		}
		if !self.password_regex.is_match(password.as_str()) {
			return Err(UserCreationError::BadPassword)
		}
		if self.user_cred_map.read().unwrap().contains_key(&username) {
			return Err(UserCreationError::UsernameInUse)
		}

		self.user_cred_map.write().unwrap().insert(username, Credential::PasswordHash(
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

	pub fn delete_user(&self, username: &String) -> bool {
		self.user_cred_map.write().unwrap().remove(username).is_some()
	}

	/// Try to login with the given credentials
	pub fn try_login_password(&self, username: &String, password: String) -> LoginResult {
		let reader = self.failed_logins.read().unwrap();

		if let Some(fail) = reader.get(username) {
			if fail.running_count >= self.max_fails {
				if fail.time.elapsed() <= self.lockout_time {
					return LoginResult::LockedOut
				} else {
					drop(reader);
					self.failed_logins.write().unwrap().remove(username);
				}
			} else if fail.time.elapsed() > self.lockout_time {
				// The last fail was too long ago
				self.failed_logins.write().unwrap().remove(username);
			}
		} else {
			drop(reader)
		}

		match self.user_cred_map.read().unwrap().get(username) {
			Some(Credential::PasswordHash(hash)) =>
				if argon2::verify_encoded(hash.as_str(), password.as_bytes()).unwrap() {

					if self.failed_logins.read().unwrap().contains_key(username) {
						self.failed_logins.write().unwrap().remove(username);
					}

					LoginResult::Ok
				} else {
					let mut writer = self.failed_logins.write().unwrap();

					if let Some(fail) = writer.get_mut(username) {
						fail.running_count += 1;
						fail.time = Instant::now();
						if fail.running_count == self.max_fails {
							FAILED_LOGINS.warn(username.clone(), None);
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

	/// Try to login with the given credentials
	pub fn try_login_key(&self, username: &String, challenge: String, signature: Signature) -> LoginResult {
		match self.user_cred_map.read().unwrap().get(username) {
			Some(Credential::PasswordHash(_)) => LoginResult::UnexpectedCredentials,
			Some(Credential::Key(key)) => {
				if !challenge.starts_with(&self.key_challenge_prefix) {
					return LoginResult::BadCredentialChallenge
				}

				let mut used_challenges = self.used_challenges.lock().unwrap();
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
	/// Is the given user able to create a user?
	pub fn can_user_create_user(&self, username: &String) -> bool {
		if let Some(privileges) = self.privileged.get(username) {
			privileges.contains(&Privilege::CreateUser)
		} else {
			false
		}
	}
}


impl SessionID {
	/// Create a random session ID
	///
	/// May or may not already exist
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
	/// Creates a Sessions instance that has a separate task that performs occasional cleanups
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
				out_clone.prune_expired();
			}
		});

		out
	}

	/// Create a new session for the given user
	///
	/// If the user has already opened a session and it has not expired yet, it will be returned
	///
	/// Does not check if the user has been authenticated
	pub fn create_session(&self, username: String) -> Arc<SessionID> {
		if let Some(x) = self.user_session_map.read().unwrap().get(&username) {
			return x.clone()
		}

		let mut writer = self.sessions.write().unwrap();
		let mut session_id;

		{
			let mut rand_gen = thread_rng();
			session_id = SessionID::new(&mut rand_gen);

			while writer.contains_key(&session_id) {
				session_id = SessionID::new(&mut rand_gen)
			}
		}

		let arc_session_id = Arc::new(session_id);
		writer.insert(arc_session_id.clone(), SessionData {
			creation_time: Instant::now(),
			owning_user: username.clone()
		});
		drop(writer);

		self.user_session_map.write().unwrap().insert(username.clone(), arc_session_id.clone());
		self.session_user_map.write().unwrap().insert(arc_session_id.clone(), username);

		arc_session_id
	}

	/// Remove expired sessions
	fn prune_expired(&self) {
		let mut session_writer = self.sessions.write().unwrap();
		let old_sessions = replace(session_writer.deref_mut(), HashMap::new());
		let mut user_session_writer = self.user_session_map.write().unwrap();
		let mut session_user_writer = self.session_user_map.write().unwrap();

		for (session_id, session_data) in old_sessions {
			if session_data.creation_time.elapsed() > self.max_session_duration {
				user_session_writer.remove(&session_data.owning_user);
				session_user_writer.remove(&session_id);
			} else {
				session_writer.insert(session_id, session_data);
			}
		}
	}

	/// Does the given session exist and is not expired?
	pub fn is_valid_session(&self, session_id: &SessionID) -> bool {
		self.sessions.read().unwrap().contains_key(session_id)
	}

	/// Get the username that owns the given session
	pub fn get_session_owner(&self, session_id: &SessionID) -> Option<String> {
		self.session_user_map.read().unwrap().get(session_id).cloned()
	}
}


impl Pipes {
	/// Creates a Pipes instance that has a separate task that performs occasional cleanups
	pub fn new(bind_addr: String, cleanup_delay: u32, is_local: bool) -> Arc<Self> {
		let out = Arc::new(Self {
			free_pipes: Default::default(),
			bind_addr: String::from(MANGLE_DB_SUFFIX) + bind_addr.as_str(),
			is_local
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_pipes();
			}
		});

		out
	}

	/// Take a pipe from self
	///
	/// If there are no pipes to take, a new one will be generated
	pub async fn take_pipe(&self) -> Result<EitherPipe, IOError> {
		{
			if let Some(x) = self.free_pipes.lock().unwrap().pop() {
				return Ok(x)
			}
		}

		if self.is_local {
			EitherPipe::connect_local(self.bind_addr.as_str())
		} else {
			EitherPipe::connect_remote(self.bind_addr.as_str()).await
		}
	}

	/// Return a pipe to self
	///
	/// Do not return if the pipe generated an error while being used
	pub fn return_pipe(&self, pipe: EitherPipe) {
		self.free_pipes.lock().unwrap().push(pipe);
	}

	/// Drop all pipes
	///
	/// During periods of high activities, many pipes might be generated.
	/// After the traffic subsides, some memory will still be allocated to save pipes
	/// that are no longer needed. Dropping all pipes forces each call to take_pipe to
	/// create pipes when needed, which will cause the number of pipes to match the new level of traffic
	fn prune_pipes(&self) {
		self.free_pipes.lock().unwrap().clear();
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

	/// Can an anonymous user (unauthenticated) read at this location?
	///
	/// Anonymous users can never write
	pub fn can_anonymous_read_here(&self, path: &PathBuf) -> bool {
		self.public_read_paths.partial_contains(path_buf_to_segments(path))
	}

	/// Can a user write at this location?
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

	/// Can a user read at this location?
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
