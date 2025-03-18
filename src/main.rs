use blake3::Hasher;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, Read};
use std::path::Path;

fn main() {
    let input = io::stdin().lock();

    for line in input.lines() {
        let Ok(line) = line else {
            println!("ERROR Couldn't read line");
            break;
        };

        let parts = line.splitn(2, ' ');

        if let Err(err) = handle_message(parts) {
            println!("ERROR {}", err);
            break;
        }
    }
}

fn handle_message<'a>(mut parts: impl Iterator<Item = &'a str>) -> Result<(), &'static str> {
    match parts.next().ok_or("Invalid message")? {
        "GETVERSION" => {
            println!("VERSION 1");
        }
        "CANVERIFY" => {
            println!("CANVERIFY-YES");
        }
        "ISSTABLE" => {
            println!("ISSTABLE-YES");
        }
        "ISCRYPTOGRAPHICALLYSECURE" => {
            println!("ISCRYPTOGRAPHICALLYSECURE-YES");
        }
        "GENKEY" => {
            let filepath = parts.next().ok_or("Invalid message")?;

            match generate_key(filepath) {
                Ok(key) => println!("GENKEY-SUCCESS {}", key),
                Err(err) => println!("GENKEY-FAILURE {}", err),
            }
        }
        "VERIFYKEYCONTENT" => {
            let key = parts.next().ok_or("Invalid message".into())?;
            let filepath = parts.next().ok_or("Invalid message".into())?;

            match verify_key_content(key, filepath) {
                Ok(_) => println!("VERIFYKEYCONTENT-SUCCESS"),
                Err(err) => println!("VERIFYKEYCONTENT-FAILURE"),
            }
        }
        _ => return Err("Invalid message"),
    }

    Ok(())
}

fn generate_key(filepath: &str) -> io::Result<String> {
    todo!()
}

fn verify_key_content(key: &str, filepath: &str) -> io::Result<()> {
    todo!()
}
