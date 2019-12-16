use std::io::Cursor;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use base32::Alphabet::RFC4648;
use byteorder::{BigEndian, ReadBytesExt};
use err_derive::Error;
use ring::hmac;
use url::{ParseError, Url};

// -----------------------------------------------------------------------------
// Consts
// -----------------------------------------------------------------------------

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u8 = 6;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Error)]
pub enum Error {
    #[error(display = "invalid digits provided")]
    InvalidDigits(String),

    #[error(display = "invalid secret")]
    InvalidSecret(String),

    #[error(display = "invalid token url")]
    InvalidTokenURL(#[error(source)] ParseError),
}

// -----------------------------------------------------------------------------
// Types - Authenticator
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Authenticator {
    digits: u8,
    secret: Vec<u8>,
}

impl Authenticator {
    pub fn new<T: Into<Vec<u8>>, L: Into<u8>>(secret: T, digits: L) -> Authenticator {
        Authenticator {
            secret: secret.into(),
            digits: digits.into(),
        }
    }

    pub fn from_base32<T: Into<String>, L: Into<u8>>(
        encoded_secret: T,
        digits: L,
    ) -> Result<Authenticator, Error> {
        match base32::decode(RFC4648 { padding: false }, &encoded_secret.into())
            .map(|secret| Authenticator::new(secret, digits.into()))
        {
            Some(a) => Ok(a),
            None => Err(Error::InvalidSecret("invalid encoded secret".to_string())),
        }
    }

    pub fn from_token_url<T: Into<String>>(token: T) -> Result<Authenticator, Error> {
        let token_url = match Url::parse(&token.into()) {
            Ok(u) => u,
            Err(err) => return Err(Error::InvalidTokenURL(err)),
        };

        let mut digits: u8 = DEFAULT_DIGITS;
        let mut secret: String = "".to_string();
        for (k, v) in token_url.query_pairs() {
            if k == "digits" {
                let string_digits: String = v.into_owned();
                digits = match string_digits.parse::<u8>() {
                    Ok(d) => d,
                    Err(err) => return Err(Error::InvalidDigits(format!("{:?}", err))),
                };
            } else if k == "secret" {
                secret = v.into_owned();
            }
        }

        if digits > 9 || digits < 6 {
            return Err(Error::InvalidDigits(format!(
                "{} is not valid digits for code length, must be between 6-9",
                digits
            )));
        }

        if secret == "" {
            return Err(Error::InvalidSecret("empty secret".to_string()));
        }

        Authenticator::from_base32(secret, digits)
    }

    pub fn generate_totp(&self) -> u32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.generate_hotp(timestamp / DEFAULT_PERIOD)
    }

    pub fn generate_hotp(&self, counter: u64) -> u32 {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.secret);
        let tag = hmac::sign(&key, &counter.to_be_bytes());
        let digest = tag.as_ref();
        let offset = (digest[19] & 15) as usize;
        let mut reader = Cursor::new(digest[offset..offset + 4].to_vec());
        let code = reader.read_u32::<BigEndian>().unwrap() & 0x7fff_ffff;
        code % (10u32).overflowing_pow(self.digits as u32).0
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::Authenticator;

    #[test]
    fn from_token_url() {
        let token_url =
            "otpauth://totp/localhost?secret=MZQWWZLTMVRXEZLU&issuer=localhost&digits=6";
        assert_eq!(
            Authenticator::from_token_url(token_url)
                .unwrap()
                .generate_hotp(0),
            937044
        );

        assert_eq!(
            Authenticator::from_base32("MZQWWZLTMVRXEZLU", 6)
                .unwrap()
                .generate_hotp(0),
            937044
        );
    }

    #[test]
    fn generate_hotp() {
        assert_eq!(Authenticator::new("fakesecret", 6).generate_hotp(0), 937044);

        assert_eq!(
            Authenticator::new("fakesecret", 7).generate_hotp(0),
            1937044
        );

        assert_eq!(
            Authenticator::new("fakesecret", 8).generate_hotp(0),
            41937044
        );

        assert_eq!(
            Authenticator::new("fakesecret", 9).generate_hotp(0),
            741937044
        );
    }
}
