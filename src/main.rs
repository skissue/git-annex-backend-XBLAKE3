use blake3::Hasher;
use std::io::{self, BufRead};
use std::path::Path;

fn main() {
    let input = io::stdin().lock();

    for line in input.lines() {
        let Ok(line) = line else {
            println!("ERROR Couldn't read line");
            break;
        };

        let (message, arguments) = line.split_once(' ').unwrap_or((&line, ""));

        match handle_message(message, arguments) {
            Ok(response) => println!("{}", response),
            Err(err) => {
                println!("ERROR {}", err);
                break;
            }
        }
    }
}

fn handle_message<'a>(message: &str, arguments: &str) -> Result<String, &'static str> {
    match message {
        "GETVERSION" => Ok("VERSION 1".to_string()),
        "CANVERIFY" => Ok("CANVERIFY-YES".to_string()),
        "ISSTABLE" => Ok("ISSTABLE-YES".to_string()),
        "ISCRYPTOGRAPHICALLYSECURE" => Ok("ISCRYPTOGRAPHICALLYSECURE-YES".to_string()),
        "GENKEY" => {
            let filepath = arguments;

            let file_size = match file_size(filepath) {
                Ok(size) => size,
                Err(err) => return Ok(format!("GENKEY-FAILURE {}", err)),
            };

            match generate_key(filepath) {
                Ok(key) => Ok(format!("GENKEY-SUCCESS XBLAKE3-s{}--{}", file_size, key)),
                Err(err) => Ok(format!("GENKEY-FAILURE {}", err)),
            }
        }
        "VERIFYKEYCONTENT" => {
            let (key, filepath) = arguments.split_once(" ").ok_or("Invalid message")?;

            if verify_key_content(key, filepath) {
                Ok("VERIFYKEYCONTENT-SUCCESS".to_string())
            } else {
                Ok("VERIFYKEYCONTENT-FAILURE".to_string())
            }
        }
        _ => Err("Invalid message"),
    }
}

fn file_size(filepath: &str) -> io::Result<u64> {
    let metadata = std::fs::metadata(filepath)?;

    Ok(metadata.len())
}

fn generate_hash(filepath: &str) -> io::Result<blake3::Hash> {
    let path = Path::new(filepath);
    let mut hasher = Hasher::new();

    hasher.update_mmap_rayon(path)?;

    Ok(hasher.finalize())
}

fn generate_key(filepath: &str) -> io::Result<String> {
    let hash = generate_hash(filepath)?;

    Ok(hash.to_string())
}

fn verify_key_content(key: &str, filepath: &str) -> bool {
    let Some((_, key)) = key.split_once("--") else {
        return false;
    };

    let Ok(hash) = generate_hash(filepath) else {
        return false;
    };

    blake3::Hash::from_hex(key)
        .map(|k| k == hash)
        .unwrap_or(false)
}
