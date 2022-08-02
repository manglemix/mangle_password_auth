use std::collections::HashSet;
use std::convert::Infallible;
use std::str::FromStr;

use simple_serde::{DeserializationError, DeserializationErrorKind, Deserialize, ReadableProfile, Serialize, Serializer};

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
	pub hash: String,
	pub privileges: HashSet<Privilege>
}


impl Deserialize<ReadableProfile> for UserCredentialData {
	fn deserialize<T: Serializer>(data: &mut T) -> Result<Self, DeserializationError> {
		Ok(Self {
			hash: data.deserialize_key("hash")?,
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
