use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::io;
use std::fs;
use std::fs::File;

use clap::Parser;
use colored::Colorize;

use sha3::digest::generic_array::GenericArray;
use sha3::{Digest, Sha3_256};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm // Or `Aes128Gcm`
};

mod utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Decrypt file
    #[arg(long, short, action)]
    decrypt: bool,

    /// file
    #[clap(group = "input")]
    input_file: String
}

fn main() {
    let args = Args::parse();

    let path = Path::new(&args.input_file);
    if !path.is_file() {
        println!("{}", "Not a file or it doesn't exists...".red());
        process::exit(1);
    }

    let stdin = io::stdin();
    let mut input = &mut String::new();
    print!("{}", "Enter password: ".blue());
    io::stdout().flush().unwrap();
    stdin.read_line(&mut input).unwrap();

    println!("{}", "Reading the file...".yellow());
    let data: Vec<u8>;
    match fs::read(path) {
        Ok(f_data) => data = f_data,
        Err(_) => {
            println!("{}", "Failed to read file :(".red());
            process::exit(1);
        }
    }

    if !&args.decrypt {
        encrypt(path.to_path_buf(), input.to_string(), data);
    } else {
        decrypt(path.to_path_buf(), input.to_string(), data);
    }
}

fn encrypt(path: PathBuf, password: String, data: Vec<u8>) {
    println!("{}", "Encrypting...".yellow());

    let mut hasher = Sha3_256::new();
    hasher.update(password);
    let encrypt_hash = hasher.finalize();

    let mut hasher = Sha3_256::new();
    hasher.update(encrypt_hash);
    let password_hash = hasher.finalize();

    let cipher = Aes256Gcm::new(&encrypt_hash);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, &*data).unwrap();

    let output_path = utils::append_ext("encrypted", &path);

    let mut file = File::create(output_path).unwrap();
    file.write_all(&password_hash).unwrap();
    file.write_all(&nonce).unwrap();
    file.write_all(&ciphertext).unwrap();

    println!("{}", "Done.".green());
}

fn decrypt(path: PathBuf, password: String, data: Vec<u8>) {
    println!("{}", "Checking password...".yellow());
    let mut hasher = Sha3_256::new();
    hasher.update(password);
    let encrypt_hash = hasher.finalize();

    let mut hasher = Sha3_256::new();
    hasher.update(encrypt_hash);
    let password_hash = hasher.finalize();

    let file_password_hash = &data[0..32];

    if password_hash != GenericArray::clone_from_slice(file_password_hash) {
        println!("{}", "Wrong password!".red());
        process::exit(1);
    }

    let cipher = Aes256Gcm::new(&encrypt_hash);
    let nonce = GenericArray::clone_from_slice(&data[32..44]);
    let plaintext = cipher.decrypt(&nonce, &data[44..]).unwrap();
    
    let new_path = if path.extension().and_then(|ext| ext.to_str()) == Some("encrypted") {
        path.with_extension("") // Removes the last extension
    } else {
        path
    };

    fs::write(new_path, plaintext).unwrap();
    println!("{}", "Done.".green());
}