extern crate thrussh_keys;
extern crate futures;
extern crate tokio_uds;
extern crate tokio_core;
extern crate rand;
extern crate clap;
extern crate libc;

use thrussh_keys::agent;
use std::path::Path;
use rand::Rng;

fn main() {
    let matches = clap::App::new("Thrussh-agent")
        .version("0.1")
        .author("Pierre-Étienne Meunier <pe@pijul.org>")
        .arg(clap::Arg::with_name("address")
             .short("a")
             .takes_value(true)
             .help("Bind the agent to that address"))
        .arg(clap::Arg::with_name("foreground")
             .short("D")
             .help("Foreground mode"))
        .get_matches();

    let mut rng = rand::thread_rng();
    let agent_path = {
        if let Some(addr) = matches.value_of("address") {
            std::path::Path::new(addr).to_path_buf()
        } else if let Ok(tmp) = std::env::var("TMPDIR") {
            let file: String = "thrussh-".chars().chain(rng.gen_ascii_chars().take(10)).collect();
            let mut path = Path::new(&tmp).join(&file);
            path.push("agent.ppid");
            path
        } else {
            eprintln!("No $TMPDIR, and no address was given");
            std::process::exit(1)
        }
    };

    if let Some(parent) = agent_path.parent() {
        std::fs::create_dir_all(parent).unwrap()
    }

    let foreground = matches.is_present("foreground");

    let pid = if foreground {
        unsafe { libc::getpid() }
    } else {
        unsafe { libc::fork() }
    };

    if pid > 0 || foreground {

        println!("SSH_AUTH_SOCK={:?}; export SSH_AUTH_SOCK;\nSSH_AGENT_ID={}; export SSH_AGENT_ID; echo Agent pid {}", agent_path, pid, pid);

    }

    if pid == 0 || foreground {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let h = core.handle();
        let listener = tokio_uds::UnixListener::bind(&agent_path, &h).unwrap().incoming();
        core.run(agent::server::AgentServer::new(listener, h, ())).unwrap();
    }

}
