extern crate thrussh_keys;
extern crate futures;
extern crate tokio_uds;
extern crate tokio_core;
extern crate clap;
extern crate termion;

use futures::{Future, Stream};
use futures::future::Either;
use thrussh_keys::agent;
use std::path::Path;
use std::io::Read;
use std::fs::File;

fn main() {
    let matches = clap::App::new("Thrussh-add")
        .version("0.1")
        .author("Pierre-Étienne Meunier <pe@pijul.org>")
        .arg(clap::Arg::with_name("address")
             .short("a")
             .takes_value(true)
             .help("Bind the agent to that address"))
        .arg(clap::Arg::with_name("file")
             .takes_value(true)
             .multiple(true)
             .help("Secret key files to add"))
        .get_matches();

    let agent_path = {
        if let Some(addr) = matches.value_of("address") {
            std::path::Path::new(addr).to_path_buf()
        } else if let Ok(tmp) = std::env::var("SSH_AUTH_SOCK") {
            Path::new(&tmp).to_path_buf()
        } else {
            eprintln!("No $TMPDIR, and no address was given");
            std::process::exit(1)
        }
    };

    if let Some(files) = matches.values_of("file") {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let h = core.handle();
        let stream = tokio_uds::UnixStream::connect(&agent_path, &h).unwrap();
        let client = agent::client::AgentClient::connect(stream);

        core.run(
            futures::stream::iter_ok::<_, thrussh_keys::Error>(files)
                .fold(client, |client, s| {
                    let mut f = File::open(s).unwrap();
                    let mut key = String::new();
                    f.read_to_string(&mut key).unwrap();
                    let key = match thrussh_keys::decode_secret_key(&key, None) {
                        Ok(key) => Ok(key),
                        Err(_) => {
                            let password = password().unwrap();
                            thrussh_keys::decode_secret_key(&key, Some(password.as_bytes()))
                        }
                    };
                    match key {
                        Ok(key) => Either::A(client.add_identity(&key, &[]).map(move |(client, success)| {
                            if !success {
                                eprintln!("failed to add {:?}", s);
                            }
                            client
                        })),
                        Err(e) => {
                            eprintln!("Could not open key file: {:?}", e);
                            Either::B(futures::finished(client))
                        }
                    }
                })
        ).unwrap();
    }
}

fn password() -> Result<String, std::io::Error> {
    print!("Password: ");
    use std::io::{stdin, stdout};
    use termion::input::TermRead;
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();
    if let Some(pass) = stdin.read_passwd(&mut stdout)? {
        return Ok(pass)
    } else {
        return Ok(String::new())
    }
}
