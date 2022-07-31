use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Config, Error as ArgonError, hash_encoded};
use async_std::channel::{Sender, unbounded};
use async_std::sync::{Mutex, RwLock};
use ed25519_dalek::{PublicKey, Signature};
use rand::{Rng, SeedableRng};
use rand::distributions::Alphanumeric;
use rand::rngs::StdRng;
use tokio::{join, spawn};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::time::sleep;
use toml::Value;
use toml::value::Table;

use crate::*;
use crate::mangle_rust_utils::Colorize;

type ArcString = Arc<String>;
type ArcRoles = Arc<Vec<String>>;

const KEY_CHALLENGE_PREFIX: &str = "mangleDB_challenge_";


// fn roles_to_string(roles: &ArcRoles) -> String {
// 	let mut out = String::new();
// 	for role in roles.iter() {
// 		out += role.as_str();
// 		out += " ";
// 	}
// 	out.pop();
// 	out
// }


struct KeyAndFile {
	key: PublicKey,
	file: String,
}


impl Deref for KeyAndFile {
	type Target = PublicKey;

	fn deref(&self) -> &Self::Target {
		&self.key
	}
}


enum Credential {
	PasswordHash(String),
	Key(KeyAndFile),
}


pub enum AddUserError {
	HashError(ArgonError),
	NonexistentRole(String),
	UserExists,
	BadName
}


impl From<ArgonError> for AddUserError {
	fn from(e: ArgonError) -> Self {
		Self::HashError(e)
	}
}


#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserPrivileges {
	CreateUser
}


impl From<UserPrivileges> for Value {
	fn from(p: UserPrivileges) -> Self {
		match p {
			UserPrivileges::CreateUser => "can_create_user".into()
		}
	}
}


impl TryFrom<Value> for UserPrivileges {
	type Error = ();

	fn try_from(value: Value) -> Result<Self, Self::Error> {
		match value.as_str().ok_or(())? {
			"can_create_user" => Ok(Self::CreateUser),
			_ => Err(())
		}
	}
}


#[derive(Default)]
pub struct AuthState {
	// roles: (pipe, last_access_time)
	local_socket_map: Mutex<HashMap<ArcRoles, (Arc<Mutex<NamedPipeClient>>, Sender<()>)>>,
	session_user_map: RwLock<HashMap<ArcString, ArcString>>,
	user_session_map: RwLock<HashMap<ArcString, ArcString>>,
	session_roles_map: RwLock<HashMap<ArcString, ArcRoles>>,
	user_cred_map: RwLock<HashMap<ArcString, Credential>>,
	// username: credential
	user_role_map: RwLock<HashMap<ArcString, ArcRoles>>,
	user_user_map: RwLock<HashMap<ArcString, ArcString>>,
	used_challenges: RwLock<HashSet<String>>,
	local_bind_addr: RwLock<String>,
	failed_logins: RwLock<HashMap<ArcString, (u8, Instant)>>,
	lockout_time: RwLock<Duration>,
	max_fails: RwLock<u8>,
	roles: RwLock<HashSet<String>>,
	max_pipe_idle_time: RwLock<Duration>,
	max_session_duration: RwLock<Duration>,
	user_privilege_map: RwLock<HashMap<ArcString, HashSet<UserPrivileges>>>
}


impl AuthState {
	pub fn new() -> Self {
		Self::default()
	}

	pub async fn populate(
		&self,
		userdata: String,
		used_challenges: String,
		local_bind_addr: String,
		roles: String,
		lockout_time: u64,
		max_fails: u8,
		max_pipe_idle_time: u64,
		max_session_duration: u64
	) {
		join!(
			async {*self.local_bind_addr.write().await = local_bind_addr},
			async {*self.lockout_time.write().await = Duration::from_secs(lockout_time)},
			async {*self.max_fails.write().await = max_fails},
			async {*self.max_pipe_idle_time.write().await = Duration::from_secs(max_pipe_idle_time)},
			async {*self.max_session_duration.write().await = Duration::from_secs(max_session_duration)},
			async {*self.roles.write().await = roles.split('\n').map(String::from).collect()}
		);

		let table = match userdata.parse() {
			Ok(Value::Table(x)) => x,
			Ok(_) => {
				error!("The given user data is not of the right format");
				bad_exit!();
			}
			Err(e) => {
				default_error!(e, "parsing user data");
				bad_exit!();
			}
		};

		let mut user_cred_map = self.user_cred_map.write().await;
		let mut user_role_map = self.user_role_map.write().await;
		let mut user_user_map = self.user_user_map.write().await;
		let mut user_privilege_map = self.user_privilege_map.write().await;

		for (name, value) in table {
			let name = Arc::new(name);

			let user_table = unwrap_option_or_msg!(
				value.as_table(),
				"The user table for {name} is not a table"
			);

			let credential = match user_table.get("hash") {
				Some(x) => Credential::PasswordHash(match x.as_str() {
					Some(x) => String::from(x),
					None => {
						log_error!("User: {name} password hash is not a valid string");
						bad_exit!();
					}
				}),
				None => {
					let toml_key_path = unwrap_option_or_msg!(
						user_table.get("key"),
						"User: {name} has no credentials"
					);

					let key_path = String::from(unwrap_option_or_msg!(
						toml_key_path.as_str(),
						"User: {name} key filename is not a valid string"
					));

					let mut key_file = unwrap_result_or_default_error!(
						File::open(key_path.as_str()),
						"opening {key_path} key file"
					);

					let mut key_bytes = Vec::new();

					unwrap_result_or_default_error!(
						key_file.read_to_end(&mut key_bytes),
						"reading key file: {key_path}"
					);

					let key = unwrap_result_or_default_error!(
						PublicKey::from_bytes(key_bytes.as_slice()),
						"reading key file: {key_path}"
					);
					Credential::Key(
						KeyAndFile {
							key,
							file: key_path,
						}
					)
				}
			};

			let roles_toml = unwrap_option_or_msg!(
				unwrap_option_or_msg!(
					user_table.get("roles"),
					"User: {name} does not have a password hash"
				).as_array(),
				"User: {name} roles array is not a valid array"
			);

			let mut roles = Vec::new();
			for role in roles_toml {
				roles.push(String::from(unwrap_option_or_msg!(
					role.as_str(),
					"User: {name} roles array has invalid roles"
				)));
			}

			if let Some(privs) = user_table.get("privileges") {
				let mut privileges = HashSet::new();
				if let Value::Array(privs) = privs {
					for privilege in privs {
						privileges.insert(unwrap_result_or_default_error!(
							UserPrivileges::try_from(privilege.clone()),
							"deserializing privilege: {privilege}"
						));
					}
				} else {
					error!("Privileges array for {name} is not the right format");
					bad_exit!();
				}
				user_privilege_map.insert(name.clone(), privileges);
			}

			user_role_map.insert(name.clone(), Arc::new(roles));
			user_cred_map.insert(name.clone(), credential);
			user_user_map.insert(name.clone(), name);
		}

		let mut write = self.used_challenges.write().await;
		*write = used_challenges.split('\n').map(String::from).collect();
	}

	pub async fn is_valid_key(&self, username: &String, challenge: String, signature: Signature) -> bool {
		if !challenge.starts_with(KEY_CHALLENGE_PREFIX) {
			return false;
		}
		let reader = self.used_challenges.read().await;
		if reader.contains(&challenge) {
			return false;
		}
		drop(reader);
		let reader = self.user_cred_map.read().await;
		let key = match reader.get(username) {
			Some(cred) => match cred {
				Credential::Key(x) => &x.key,
				Credential::PasswordHash(_) => return false
			}
			None => return false
		};

		match key.verify_strict(challenge.as_bytes(), &signature) {
			Ok(()) => {
				let modified = self.used_challenges.write().await.insert(challenge);
				debug_assert!(modified);
				true
			}
			Err(_) => false
		}
	}

	pub async fn is_valid_password(&self, username: &String, password: &String) -> Result<bool, ArgonError> {
		if let Some(cred) = self.user_cred_map.read().await.get(username) {
			return match cred {
				Credential::PasswordHash(hash) => argon2::verify_encoded(hash, password.as_bytes()),
				Credential::Key(_) => Ok(false)
			};
		}
		Ok(false)
	}

	pub async fn increment_failed_login(&self, username: &String) {
		let new_time = Instant::now() + *self.lockout_time.read().await;
		let mut lock = self.failed_logins.write().await;
		if let Some((n, time)) = lock.get_mut(username) {
			*n += 1;
			*time = new_time;
		} else {
			drop(lock);
			let arcname = self.user_user_map.read().await.get(username).unwrap().clone();
			self.failed_logins.write().await.insert(arcname, (1, new_time));
		}
	}

	pub async fn lockout_user(&self, username: &String) {
		let arcname = self.user_user_map.read().await.get(username).unwrap().clone();
		self.failed_logins.write().await.insert(
			arcname,
			(
				*self.max_fails.read().await,
				Instant::now() + *self.lockout_time.read().await
			)
		);
	}

	pub async fn is_user_locked_out(&self, username: &String) -> bool {
		let lock = self.failed_logins.read().await;
		if let Some((n, time)) = lock.get(username) {
			if n >= self.max_fails.read().await.deref() {
				if time.elapsed() > Duration::from_secs(0) {
					drop(lock);
					self.failed_logins.write().await.remove(username);
					return false
				}
				return true
			}
		}
		false
	}

	pub async fn get_session_id(&'static self, username: &String) -> ArcString {
		// assumes username exists
		if let Some(x) = self.user_session_map.read().await.get(username) {
			return x.clone();
		}

		// create session
		let mut rand_gen = StdRng::from_entropy();
		let mut session = Arc::new((&mut rand_gen)
			.sample_iter(&Alphanumeric)
			.take(32)
			.map(char::from)
			.collect::<String>());

		// ensure session is unique
		let reader = self.session_user_map.read().await;
		while reader.contains_key(&session) {        // low chance of collisions
			session = Arc::new((&mut rand_gen)
				.sample_iter(&Alphanumeric)
				.take(32)
				.map(char::from)
				.collect::<String>());
		}
		drop(reader);

		// log the creation of a session
		let arc_username = self.user_user_map.read().await.get(username).unwrap().clone();
		join!(
			async {self.session_user_map.write().await.insert(session.clone(), arc_username.clone())},
			async {self.user_session_map.write().await.insert(arc_username.clone(), session.clone())}
		);

		// associate roles with session
		let roles = self.user_role_map.read().await.get(username).unwrap().clone();
		self.session_roles_map.write().await.insert(session.clone(), roles);
		let session_clone = session.clone();

		spawn(async move {
			sleep(*self.max_session_duration.read().await).await;
			join!(
				async {self.user_session_map.write().await.remove(&arc_username)},
				async {self.session_user_map.write().await.remove(&session)}
			);
		});

		session_clone
	}

	pub async fn get_bipipe(&'static self, roles: ArcRoles) -> Result<Arc<Mutex<NamedPipeClient>>, IOError> {
		if let Some((pipe, sender)) = self.local_socket_map.lock().await.get(&roles) {
			sender.send(()).await.expect("receiver was dropped");
			return Ok(pipe.clone());
		}

		let pipe = ClientOptions::new()
			.open(String::from(r"\\.\pipe\") + self.local_bind_addr.read().await.as_str())?;

		// lend pipe
		let mut locked = self.local_socket_map.lock().await;
		let mutex = Arc::new(Mutex::new(pipe));
		let (sender, receiver) = unbounded();
		locked.insert(roles.clone(), (mutex.clone(), sender));
		drop(locked);

		spawn(async move {
			let duration = *self.max_pipe_idle_time.read().await;
			loop {
				select! {
					() = sleep(duration) => {
						self.local_socket_map.lock().await.remove(&roles);
						return
					}
					_ = receiver.recv() => {}
				}
			}
		});

		Ok(mutex)
	}

	pub async fn get_session_roles(&self, session: &String) -> Option<ArcRoles> {
		Some(self.session_roles_map.read().await.get(session)?.clone())
	}

	pub async fn write_used_challenges<T: Write>(&self, writer: &mut T) -> Result<(), IOError> {
		let reader = self.used_challenges.read().await;
		let mut iter = reader.iter();

		match iter.next() {
			Some(x) => writer.write_all(x.as_bytes())?,
			None => return Ok(())
		}

		for challenge in iter {
			writer.write_all((String::from("\n") + challenge).as_bytes())?;
		}
		Ok(())
	}

	pub async fn write_userdata<T: Write>(&self, writer: &mut T) -> Result<(), IOError> {
		let mut user_map = Table::new();
		let privilege_map = self.user_privilege_map.read().await;
		let role_map = self.user_role_map.read().await;

		for (name, credential) in self.user_cred_map.read().await.iter() {
			let mut user_table = Table::new();

			match credential {
				Credential::PasswordHash(x) => user_table.insert(String::from("hash"), Value::String(x.clone())),
				Credential::Key(x) => user_table.insert(String::from("key"), Value::String(x.file.clone()))
			};

			user_table.insert(String::from("roles"), Value::Array(
				role_map.get(name).unwrap().iter().map(|x| { Value::String(x.clone()) }).collect()
			));

			if let Some(privs) = privilege_map.get(name) {
				user_table.insert(String::from("privileges"), Value::Array(
					privs.iter().map(|x| { (*x).into() }).collect()
				));
			}

			user_map.insert(
				String::from(name.as_str()),
				Value::Table(user_table),
			);
		}
		writer.write_all(Value::Table(user_map).to_string().as_bytes())
	}

	pub async fn add_user(&self, username: String, password: String, roles: Vec<String>) -> Result<(), AddUserError> {
		let reader = self.roles.read().await;
		if reader.contains(&username) {
			return Err(AddUserError::BadName)
		}
		for role in &roles {
			if !reader.contains(role) {
				return Err(AddUserError::NonexistentRole(role.clone()))
			}
		}
		drop(reader);

		let mut rand_gen = StdRng::from_entropy();
		let mut salt = [0u8; 32];
		rand_gen.fill(salt.as_mut_slice());
		let hash = hash_encoded(password.as_bytes(), salt.as_slice(), &Config::default())?;

		let username = Arc::new(username);

		let mut writer = self.user_user_map.write().await;
		if writer.contains_key(&username) {
			return Err(AddUserError::UserExists)
		}
		writer.insert(username.clone(), username.clone());
		drop(writer);

		join!(
			async {self.user_role_map.write().await.insert(username.clone(), Arc::new(roles))},
			async {self.user_cred_map.write().await.insert(username.clone(), Credential::PasswordHash(hash))}
		);

		Ok(())
	}

	pub async fn get_user_privileges(&self, username: &String) -> HashSet<UserPrivileges> {
		match self.user_privilege_map.read().await.get(username) {
			Some(x) => x.clone(),
			None => HashSet::new()
		}
	}

	pub async fn get_session_owner(&self, session_id: &String) -> ArcString {
		self.session_user_map.read().await.get(session_id).unwrap().clone()
	}
}