extern crate lesspass;
extern crate ring;
extern crate structopt;

use lesspass::*;
use ring::digest;
use structopt::StructOpt;

use std::io::Write;


/// Generates LessPass-like passwords.
#[derive(StructOpt)]
#[structopt(raw(after_help = r#""EXAMPLES:
    Generate a password:
      lesspass example.org contact@example.org password

    Generate the fingerprint of a master password:
      lesspass password

    Generate a 32-characters password using SHA-512:
      echo password | lesspass example.org contact@example.org --sha512 -l 32
    
    Generate the entropy of a password, using 10,000 iterations:
      lesspass example.org contact@example.org password -i 10000 -E > entropy.txt
    
    Generate an alphanumeric password using the previously saved entropy:
      cat entropy.txt | lesspass -S

    The two previous examples are obviously equivalent to:
      lesspass example.org contact@example.org password -i 10000 -S
""#))]
pub struct Args {

    /// Target website.
    #[structopt(name = "website")]
    website: Option<String>,

    /// Username or email address.
    #[structopt(name = "login")]
    login: Option<String>,

    /// Master password used for fingerprint and password generation.
    #[structopt(name = "password")]
    master_password: Option<String>,

    /// Number of iterations used for entropy generation.
    #[structopt(short = "i", long = "iterations", default_value = "100000")]
    iterations: u32,

    /// Length of the generated password.
    #[structopt(short = "l", long = "length", default_value = "16")]
    length: u8,

    /// Arbitrary number used for password generation.
    #[structopt(short = "c", long = "counter", default_value = "1")]
    counter: u8,

    /// Use SHA-256 for password generation.
    #[structopt(long = "sha256")]
    sha256: bool,

    /// Use SHA-384 for password generation.
    #[structopt(long = "sha384")]
    sha384: bool,

    /// Use SHA-512 for password generation.
    #[structopt(long = "sha512")]
    sha512: bool,

    /// Exclude lowercase characters.
    #[structopt(short = "L", long = "no-lower")]
    exclude_lower: bool,

    /// Exclude uppercase characters.
    #[structopt(short = "U", long = "no-upper")]
    exclude_upper: bool,

    /// Exclude numbers.
    #[structopt(short = "N", long = "no-numbers")]
    exclude_numbers: bool,

    /// Exclude symbols.
    #[structopt(short = "S", long = "no-symbols")]
    exclude_symbols: bool,

    /// Return the entropy instead of generating a password.
    #[structopt(short = "E", long = "return-entropy")]
    return_entropy: bool
}

fn main() {
    if let Err(err) = run() {
        let mut out = std::io::stderr();

        let res = if !err.is_empty() {
            out.write_all(err.as_bytes()).map_err(|_| ())
        } else {
            Args::clap().write_help(&mut out).map_err(|_| ())
        };

        std::process::exit(if res.is_ok() { 1 } else { 2 })
    }
}

fn run() -> Result<(), &'static str> {
    let Args {
        website, login, master_password,
        iterations, length, counter,
        sha256, sha384, sha512,
        exclude_lower, exclude_upper, exclude_numbers, exclude_symbols,
        return_entropy
    } = Args::from_args();

    let mut out = std::io::stdout();

    // Validate and find digest.
    let algorithm = match (sha256, sha384, sha512) {
        (false, false, false) |
        (true , false, false) => &digest::SHA256,
        (false, true , false) => &digest::SHA384,
        (false, false, true ) => &digest::SHA512,

        _ => return Err("Only one algorithm must be provided.")
    };

    // Validate and find allowed characters.
    let mut charset = CharacterSet::All;

    if exclude_lower { charset.remove(CharacterSet::Lowercase); }
    if exclude_upper { charset.remove(CharacterSet::Uppercase); }
    if exclude_numbers { charset.remove(CharacterSet::Numbers); }
    if exclude_symbols { charset.remove(CharacterSet::Symbols); }

    if charset.is_empty() {
        return Err("Not all characters can be excluded from the generation algorithm.")
    }

    // Validate length / counter / iterations.
    if length < 6 || length > 64 {
        return Err("The length must be an integer in the [6; 64] range.")
    }
    if counter > 99 {
        return Err("The counter must be an integer in the [0; 99] range.")
    }
    if iterations < 1 || iterations > 100_000_000 {
        return Err("The iterations must be an integer in the [1; 100,000,000] range.")
    }

    // Compute entropy.
    let entropy = match (website, login, master_password) {
        (pass, None, None) => {
            let master_password = match pass {
                Some(pass) => pass,
                None => read_stdin()? // Get password from standart input.
            };

            // If the password matches the format of the entropy, then we use it. Otherwise
            // we only return the fingerprint.
            match parse_entropy(&master_password) {
                None => {
                    // Only the password was given, so we return its fingerprint.
                    let fingerprint = get_fingerprint(&master_password);

                    for byte in fingerprint.as_ref() {
                        write!(out, "{:02x}", byte).map_err(|_| "Unable to write to standard output.")?;
                    }

                    out.write(b"\n").map_err(|_| "Unable to write to standard output.")?;

                    return Ok(())
                },
                Some(entropy) => {
                    // The entropy was given to us, so we use it instead.
                    entropy
                }
            }
        },
        (Some(website), Some(login), pass) => {
            // Everything needed to compute the entropy was given, so we get to it.
            let master_password = match pass {
                Some(pass) => pass,
                None => read_stdin()? // Get password from standart input.
            };
            let salt = generate_salt(&website, &login, counter);

            generate_entropy(&master_password, &salt, algorithm, iterations)
        },
        _ => {
            // We cannot do anything with what we were given; return an error.
            return Err("")
        }
    };

    // Compute and print password.
    if return_entropy {
        print_buffer_hex(&entropy, &mut out)?;
    } else {
        let password = render_password(&entropy, charset, length);

        println!("{}", password);
    }

    Ok(())
}

fn print_buffer_hex(buf: &[u8], out: &mut Write) -> Result<(), &'static str> {
    for byte in buf {
        write!(out, "{:02x}", byte).map_err(|_| "Unable to write to standard output.")?;
    }

    out.write(b"\n").map_err(|_| "Unable to write to standard output.")?;

    Ok(())
}

fn read_stdin() -> Result<String, &'static str> {
    let stdin = std::io::stdin();
    let mut input = String::new();

    if stdin.read_line(&mut input).is_err() {
        return Err("Unable to read value from standard input.")
    }

    // Trim string if needed.
    if input.ends_with('\n') {
        let new_len = input.len() - (if input.ends_with("\r\n") { 2 } else { 1 });

        input.truncate(new_len);
    }

    Ok(input)
}

fn parse_entropy(entropy: &str) -> Option<Vec<u8>> {
    if entropy.len() != 64 {
        return None
    }
    
    let mut vec = Vec::with_capacity(32);

    for i in 0..32 {
        vec.push(
            u8::from_str_radix(&entropy[i*2 .. i*2+2], 16).ok()?
        );
    }

    Some(vec)
}
