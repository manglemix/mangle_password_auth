use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fs::File;
use std::io::Read;
use std::mem::take;
use std::path::PathBuf;
use std::str::FromStr;

// use async_std::task::block_on;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, PublicKey};
use mangle_rust_utils::NestedMap;
use simple_serde::{DeserializationError, DeserializationErrorKind, Deserialize, ReadableProfile, Serialize, Serializer};
use simple_serde::mlist_prelude::*;

use crate::*;
use crate::singletons::Privilege;

impl Serialize<ReadableProfile> for Privilege {
	fn serialize<T: Serializer>(self, data: &mut T) {
		match self {
			Privilege::CreateUser => data.serialize_string("CreateUser")
		}
	}
}


impl Deserialize<ReadableProfile> for Privilege {
	fn deserialize<T: Serializer>(data: &mut T) -> Result<Self, DeserializationError> {
		let actual = data.deserialize_string()?;
		match actual.as_str() {
			"CreateUser" => Ok(Privilege::CreateUser),
			_ => Err(DeserializationError::new_kind(DeserializationErrorKind::NoMatch { actual }))
		}
	}
}


pub struct UserCredentialData {
	pub cred: Credential,
	pub privileges: HashSet<Privilege>
}


impl Deserialize<ReadableProfile> for UserCredentialData {
	fn deserialize<T: Serializer>(data: &mut T) -> Result<Self, DeserializationError> {
		let cred = match data.deserialize_key("hash") {
			Ok(x) => Credential::PasswordHash(x),
			Err(e) => match &e.kind {
				DeserializationErrorKind::MissingField => {
					let path: PathBuf = data.deserialize_key("key")?;
					let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
					block_on(async move {
						let mut file = unwrap_result_or_default_error!(
							File::open(path),
							"opening key file"
						);
						unwrap_result_or_default_error!(
							file.read_exact(bytes.as_mut_slice()),
							"reading key file"
						);
						Credential::Key(unwrap_result_or_default_error!(
							PublicKey::from_bytes(bytes.as_slice()),
							"parsing key file"
						))
					})
				}
				_ => return Err(e)
			}
		};

		Ok(Self {
			cred,
			privileges: data.deserialize_key_or("privileges", HashSet::new())?
		})
	}
}


pub struct UsedChallenges(pub(crate) HashSet<String>);


impl FromStr for UsedChallenges {
	type Err = Infallible;

	fn from_str(string: &str) -> Result<Self, Self::Err> {
		let mut out = HashSet::with_capacity(string.matches('\n').count() + 1);
		for line in string.split('\n') {
			out.insert(line.into());
		}
		Ok(Self(out))
	}
}


pub struct PermissionsDeser(HashMap<String, Vec<PathBuf>>);


impl Deserialize<ReadableProfile> for PermissionsDeser {
	fn deserialize<T: Serializer>(data: &mut T) -> Result<Self, DeserializationError> {
		Ok(Self(data.deserialize()?))
	}
}


impl PermissionsDeser {
	fn arr_to_map(arr: Option<Vec<PathBuf>>) -> NestedMap<String, ()> {
		if let Some(x) = arr {
			let mut out = NestedMap::new();
			for path in x {
				out.insert_item(path_buf_to_segments(&path), ());
			}
			out
		} else {
			NestedMap::new()
		}
	}

	pub fn get_public_read_paths(&mut self) -> NestedMap<String, ()> {
		Self::arr_to_map(self.0.remove("PublicRead"))
	}

	pub fn get_all_users_home_read_paths(&mut self) -> NestedMap<String, ()> {
		Self::arr_to_map(self.0.remove("AllUsersHomeRead"))
	}

	pub fn get_all_users_home_write_paths(&mut self) -> NestedMap<String, ()> {
		Self::arr_to_map(self.0.remove("AllUsersHomeWrite"))
	}

	pub fn get_all_users_extern_read_paths(&mut self) -> NestedMap<String, ()> {
		Self::arr_to_map(self.0.remove("AllUsersExternRead"))
	}

	pub fn get_all_users_extern_write_paths(&mut self) -> NestedMap<String, ()> {
		Self::arr_to_map(self.0.remove("AllUsersExternWrite"))
	}

	pub fn get_users_read_paths(&mut self) -> HashMap<String, NestedMap<String, ()>> {
		let mut out = HashMap::new();

		for (key, paths) in take(&mut self.0) {
			if key.ends_with("Read") {
				out.insert(key, Self::arr_to_map(Some(paths)));
			} else {
				assert!(key.ends_with("Write"), "{}", format!("{key} does not end with Read or Write"));
				self.0.insert(key, paths);
			}
		}

		out
	}

	pub fn get_users_write_paths(&mut self) -> HashMap<String, NestedMap<String, ()>> {
		let mut out = HashMap::new();

		for (key, paths) in take(&mut self.0) {
			if key.ends_with("Write") {
				out.insert(key, Self::arr_to_map(Some(paths)));
			} else {
				assert!(key.ends_with("Read"), "{}", format!("{key} does not end with Read or Write"));
				self.0.insert(key, paths);
			}
		}

		out
	}

	pub fn get_user_home_parent(&mut self) -> Option<Vec<String>> {
		self.0.remove("UserHomeParent").map(|mut x| {
			if x.len() != 1 {
				block_on(async { error!("UserHomeParent can only have 1 path") });
				bad_exit!();
			}
			let path = x.pop().unwrap();
			path.components().map(|x| x.as_os_str().to_str().map(|x| x.to_string())).flatten().collect()
		})
	}
}


impl_mlist_deser!(PermissionsDeser, ReadableProfile);
