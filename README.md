lesspass.rs
===========

An (unofficial) fully featured Rust client for [LessPass](https://lesspass.com).

This client is focused on performances: allocations were avoided wherever possible,
and some parts of the password generation algorithms were sligthly changed to avoid
needless allocations.


## Usage
```
Generates LessPass-like passwords.

USAGE:
    lesspass.exe [FLAGS] [OPTIONS] [ARGS]

FLAGS:
    -L, --no-lower          Exclude lowercase characters.
    -N, --no-numbers        Exclude numbers.
    -S, --no-symbols        Exclude symbols.
    -U, --no-upper          Exclude uppercase characters.
    -h, --help              Prints help information
    -E, --return-entropy    Return the entropy instead of generating a password.
        --sha256            Use SHA-256 for password generation.
        --sha384            Use SHA-384 for password generation.
        --sha512            Use SHA-512 for password generation.
    -V, --version           Prints version information

OPTIONS:
    -c, --counter <counter>          Arbitrary number used for password generation. [default: 1]
    -i, --iterations <iterations>    Number of iterations used for entropy generation. [default: 100000]
    -l, --length <length>            Length of the generated password. [default: 16]

ARGS:
    <website>     Target website.
    <login>       Username or email address.
    <password>    Master password used for fingerprint and password generation.

EXAMPLES:
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

    The two previous examples are equivalent to:
      lesspass example.org contact@example.org password -i 10000 -S
```

## Benchmarks

Even though the Python implementation uses hashlib behind the scenes and is therefore
pretty fast, this Rust implementation manages to more than double the speed of execution.

Comparing Python and Rust applications for performance is not very relevant, but
it should at least tell you that this implementation should fit your needs.

#### [lesspass-cli](https://github.com/lesspass/lesspass/tree/master/cli)
```
$ lesspass example.org contact@example.org password -L 32
139 ms
```

#### [lesspass.rs](#)
```
$ lesspass example.org contact@example.org password -l 32
64 ms
```
