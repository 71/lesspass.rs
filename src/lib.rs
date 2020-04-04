#[macro_use] extern crate bitflags;
#[macro_use] extern crate lazy_static;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate ring;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::cast::ToPrimitive;

use ring::{digest, digest::Algorithm, hmac, pbkdf2};


bitflags! {
    /// A flag that describes what characters are allowed when generating a password.
    pub struct CharacterSet: u8 {
        const Uppercase = 0b0001;
        const Lowercase = 0b0010;
        const Numbers   = 0b0100;
        const Symbols   = 0b1000;

        const Letters   = Self::Uppercase.bits | Self::Lowercase.bits;
        const All       = Self::Letters.bits | Self::Numbers.bits | Self::Symbols.bits;
    }
}

impl CharacterSet {
    const LOWERCASE: &'static str = "abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NUMBERS  : &'static str = "0123456789";
    const SYMBOLS  : &'static str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    /// Return a string that contains all the characters that may be used to generate a password.
    pub fn get_characters(self) -> &'static str {
        match (self.contains(Self::Lowercase), self.contains(Self::Uppercase), self.contains(Self::Numbers), self.contains(Self::Symbols)) {
            (true , true , true , true ) => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (true , true , true , false) => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            (true , true , false, true ) => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (true , true , false, false) => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",

            (true , false, true , true ) => "abcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (true , false, true , false) => "abcdefghijklmnopqrstuvwxyz0123456789",
            (true , false, false, true ) => "abcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (true , false, false, false) => Self::LOWERCASE,

            (false, true , true , true ) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (false, true , true , false) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            (false, true , false, true ) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (false, true , false, false) => Self::UPPERCASE,

            (false, false, true , true ) => "0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            (false, false, true , false) => Self::NUMBERS,
            (false, false, false, true ) => Self::SYMBOLS,

            _ => ""
        }
    }

    /// Return a vector of all the sets of characters that may be used to generate a password.
    pub fn get_sets(self) -> Vec<&'static str> {
        let mut sets = Vec::with_capacity(4);

        if self.contains(Self::Lowercase) {
            sets.push(Self::LOWERCASE);
        }
        if self.contains(Self::Uppercase) {
            sets.push(Self::UPPERCASE);
        }
        if self.contains(Self::Numbers) {
            sets.push(Self::NUMBERS);
        }
        if self.contains(Self::Symbols) {
            sets.push(Self::SYMBOLS);
        }

        // Ensure we didn't reallocate.
        debug_assert!(sets.capacity() == 4);

        sets
    }
}


/// Generate the salt needed to compute the entropy using a combinaison of the
/// target website, login and counters.
pub fn generate_salt(website: &str, username: &str, counter: u8) -> Vec<u8> {
    let counter_len = if counter < 16 { 1 } else { 2 };
    let mut salt = Vec::with_capacity(website.len() + username.len() + counter_len);

    let cap = salt.capacity();

    salt.extend_from_slice(website.as_bytes());
    salt.extend_from_slice(username.as_bytes());

    if counter < 16 {
        salt.push(HEX[counter as usize]);
    } else {
        salt.push(HEX[( counter & 0b0000_1111      ) as usize]);
        salt.push(HEX[((counter & 0b1111_0000) >> 4) as usize]);
    }

    // Ensure we didn't reallocate.
    debug_assert!(salt.capacity() == cap);

    salt
}

/// Generate the entropy needed to render the end password using a previously computed salt and a master password.
pub fn generate_entropy(master_password: &str, salt: &[u8], algorithm: &'static Algorithm, iterations: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);

    unsafe {
        // Not cool yes, but it allows us to avoid initializing the memory.
        out.set_len(32);
    }

    pbkdf2::derive(algorithm, iterations, salt, master_password.as_bytes(), &mut out);

    out
}

/// Generate a password of the given length using the provided entropy and character sets.
pub fn render_password(entropy: &[u8], charset: CharacterSet, len: u8) -> String {
    assert!(len >= 6 && len <= 64);

    let chars = charset.get_characters().as_bytes();
    let sets  = charset.get_sets();

    let max_len = len as usize - sets.len();
    let chars_len = BigUint::from(chars.len());


    // Generate initial part of the password.
    let mut password_chars = Vec::with_capacity(max_len + sets.len());
    let mut quotient = BigUint::from_bytes_be(entropy);

    for _ in 0..max_len {
        let rem = div_rem(&mut quotient, &chars_len);

        password_chars.push(chars[rem]);
    }


    // Compute some random characters in each set in order to ensure all sets
    // will be used at least once.
    let mut additional_chars = Vec::with_capacity(sets.len());

    for set in &sets {
        let rem = div_rem(&mut quotient, match set.len() {
            10 => &BIGUINT10,
            26 => &BIGUINT26,
            32 => &BIGUINT32,
            _  => unreachable!()
        });

        additional_chars.push(set.as_bytes()[rem]);
    }

    // Ensure we didn't reallocate.
    debug_assert!(additional_chars.capacity() == sets.len());
    debug_assert!(additional_chars.len() == sets.len());


    // Finalize last part of password using previously generated characters.
    let mut password_len = BigUint::from(password_chars.len());

    for ch in additional_chars {
        let rem = div_rem(&mut quotient, &password_len);

        password_chars.insert(rem, ch);
        password_len += &BIGINT1 as &BigUint;
    }

    // Ensure we didn't reallocate.
    debug_assert!(password_chars.capacity() == max_len + sets.len());
    debug_assert!(password_chars.capacity() == password_chars.len());

    unsafe {
        String::from_utf8_unchecked(password_chars)
    }
}

/// Return the SHA-256 fingerprint that corresponds to the given master password.
pub fn get_fingerprint(password: &str) -> hmac::Signature {
    let key = hmac::SigningKey::new(&digest::SHA256, password.as_bytes());

    hmac::sign(&key, b"")
}


lazy_static! {
    static ref BIGINT1  : BigUint = BigUint::from(1u32);
    static ref BIGUINT26: BigUint = BigUint::from(26u32);
    static ref BIGUINT32: BigUint = BigUint::from(32u32);
    static ref BIGUINT10: BigUint = BigUint::from(10u32);
}

const HEX: &[u8] = b"0123456789ABCDEF";

#[inline]
fn div_rem(quot: &mut BigUint, div: &BigUint) -> usize {
    let (new_quot, rem) = quot.div_rem(div);

    *quot = new_quot;

    match rem.to_u64() {
        Some(rem) => rem as usize,
        None => unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint() {
        // For keys with messages smaller than SHA256's block size (64
        // bytes), the key is padded with zeros.
        assert_eq!(get_fingerprint("").as_ref(),
                   &[182, 19, 103, 154, 8, 20, 217, 236, 119, 47, 149, 215, 120,
                     195, 95, 197, 255, 22, 151, 196, 147, 113, 86, 83, 198,
                     199, 18, 20, 66, 146, 197, 173]);
        assert_eq!(get_fingerprint("foo").as_ref(),
                   &[104, 55, 22, 217, 215, 248, 46, 237, 23, 76, 108, 174, 190,
                     8, 110, 233, 51, 118, 199, 157, 124, 97, 221, 103, 14, 160,
                     15, 127, 141, 110, 176, 168]);
        // If it matches the block size, it is used as-is.
        assert_eq!(get_fingerprint("0123456789abcdef0123456789abcdef\
                                    0123456789abcdef0123456789abcdef").as_ref(),
                   &[8, 18, 71, 220, 104, 187, 127, 175, 191, 19, 34, 0, 19,
                     160, 171, 113, 219, 139, 98, 141, 103, 145, 97, 248, 123,
                     94, 91, 217, 225, 155, 20, 148]);
        // If it is larger, it is hashed first.
        assert_eq!(get_fingerprint("0123456789abcdef0123456789abcdef\
                                    0123456789abcdef0123456789abcdef\
                                    larger than SHA256's block size").as_ref(),
                   &[46, 55, 32, 12, 232, 162, 61, 209, 182, 227, 200, 183, 211,
                     185, 6, 171, 72, 182, 239, 151, 196, 213, 132, 130, 106,
                     95, 106, 71, 156, 0, 103, 234]);
    }
}
