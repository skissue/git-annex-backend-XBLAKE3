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

            let file_size = match file_size(filepath) {
                Ok(size) => size,
                Err(err) => {
                    println!("GENKEY-FAILURE {}", err);
                    return Ok(());
                }
            };

            match generate_key(filepath) {
                Ok(key) => println!("GENKEY-SUCCESS XBLAKE3-s{}-{}", file_size, key),
                Err(err) => println!("GENKEY-FAILURE {}", err),
            }
        }
        "VERIFYKEYCONTENT" => {
            let key = parts.next().ok_or("Invalid message".into())?;
            let filepath = parts.next().ok_or("Invalid message".into())?;

            if verify_key_content(key, filepath) {
                println!("VERIFYKEYCONTENT-SUCCESS")
            } else {
                println!("VERIFYKEYCONTENT-FAILURE")
            }
        }
        _ => return Err("Invalid message"),
    }

    Ok(())
}

fn file_size(filepath: &str) -> io::Result<u64> {
    let metadata = std::fs::metadata(filepath)?;

    Ok(metadata.len())
}

fn generate_hash(filepath: &str) -> io::Result<blake3::Hash> {
    let path = Path::new(filepath);
    let mut hasher = Hasher::new();

    hasher.update_mmap(path)?;

    Ok(hasher.finalize())
}

fn generate_key(filepath: &str) -> io::Result<String> {
    let hash = generate_hash(filepath)?;

    Ok(hash.to_string())
}

fn verify_key_content(key: &str, filepath: &str) -> bool {
    let Ok(hash) = generate_hash(filepath) else {
        return false;
    };

    blake3::Hash::from_hex(key)
        .map(|k| k == hash)
        .unwrap_or(false)
}
