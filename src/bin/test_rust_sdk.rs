use attos_client::AttosMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut key = String::new();
    let mut serve = false;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--key" && i + 1 < args.len() {
            key = args[i + 1].clone();
            i += 1;
        } else if args[i] == "--serve" {
            serve = true;
        }
        i += 1;
    }

    if key.is_empty() && !serve {
        eprintln!("Usage: test_rust_sdk --key <key> or --serve");
        std::process::exit(1);
    }

    let map = match AttosMap::open("../scripts/staging/data.nh") {
        Ok(m) => Arc::new(m),
        Err(e) => {
            eprintln!(r#"{{"status": "error", "message": "{}"}}"#, e);
            std::process::exit(1);
        }
    };

    if serve {
        println!("Starting Rust SDK harness on :8082");
        let listener = TcpListener::bind("0.0.0.0:8082").unwrap();
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let map_clone = Arc::clone(&map);
                    std::thread::spawn(move || {
                        let mut buf = [0; 1024];
                        if let Ok(n) = stream.read(&mut buf) {
                            let request = String::from_utf8_lossy(&buf[..n]);
                            if request.starts_with("GET /lookup?key=") {
                                let parts: Vec<&str> = request.split(' ').collect();
                                if parts.len() > 1 {
                                    let path = parts[1];
                                    if let Some(k) = path.strip_prefix("/lookup?key=") {
                                        let out = do_lookup(&map_clone, k, false);
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                                            out
                                        );
                                        let _ = stream.write_all(response.as_bytes());
                                    }
                                }
                            }
                        }
                    });
                }
                Err(_) => {}
            }
        }
    } else {
        do_lookup(&map, &key, true);
    }
}

fn do_lookup(map: &AttosMap, key: &str, print: bool) -> String {
    let result = match map.get_string(key) {
        Ok(v) => format!(r#"{{"key": "{}", "value": "{}", "status": "found"}}"#, key, v),
        Err(_) => format!(r#"{{"key": "{}", "value": null, "status": "not_found"}}"#, key),
    };
    if print {
        println!("{}", result);
    }
    result
}
