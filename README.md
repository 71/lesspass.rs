lesspass.rs
===========

An (unofficial) fully featured Rust client for [LessPass](https://lesspass.com).

This client is focused on performances, and uses [Ring](https://briansmith.org/rustdoc/ring) behind the scenes.  
Allocations were avoided wherever possible, and some parts of the password generation algorithms were sligthly
changed to avoid needless allocations.


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

    The two previous examples are obviously equivalent to:
      lesspass example.org contact@example.org password -i 10000 -S
```

## Benchmarks

Although benchmarking against a Node.JS app is not very fair, the following results were obtained
when generating a password.

#### [lesspass-cli](https://www.npmjs.com/package/lesspass-cli)
```
$ lesspass example.org contact@example.org password -L 32
322 ms
```

#### [lesspass.rs](#)
```
$ lesspass example.org contact@example.org password -l 32
53 ms
```
