//! pixelcipher - embed and extract secret text messages in PNG pixel
//! data using least-significant-bit steganography, with optional
//! AES-256-GCM encryption. A classic, purely educational data-hiding
//! demo -- not a tool for evading any security control.

use clap::{Parser, Subcommand};
use image::ImageFormat;
use pixelcipher::{crypto, payload::Payload, stego};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "pixelcipher", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Embed a secret message into a PNG's pixel data.
    Embed {
        /// Cover image (PNG) to embed into
        #[arg(long = "in")]
        input: PathBuf,
        /// Output PNG with the message embedded
        #[arg(long = "out")]
        output: PathBuf,
        /// The secret message to embed
        #[arg(long)]
        message: String,
        /// Encrypt the message with AES-256-GCM using this passphrase
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Extract a secret message from a PNG's pixel data.
    Extract {
        /// Stego PNG to extract the message from
        #[arg(long = "in")]
        input: PathBuf,
        /// Passphrase, if the message was embedded with one
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Print how many bytes of message an image could hold.
    Capacity {
        /// Image to check
        #[arg(long = "in")]
        input: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Embed { input, output, message, passphrase } => {
            run_embed(&input, &output, &message, passphrase.as_deref())
        }
        Command::Extract { input, passphrase } => run_extract(&input, passphrase.as_deref()),
        Command::Capacity { input } => run_capacity(&input),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load_rgba(path: &PathBuf) -> Result<image::RgbaImage, String> {
    image::open(path)
        .map_err(|e| format!("failed to open image {}: {e}", path.display()))
        .map(|img| img.to_rgba8())
}

fn run_embed(
    input: &PathBuf,
    output: &PathBuf,
    message: &str,
    passphrase: Option<&str>,
) -> Result<(), String> {
    let mut img = load_rgba(input)?;

    let payload = if let Some(pass) = passphrase {
        let (salt, nonce, ciphertext) = crypto::encrypt(message.as_bytes(), pass)?;
        Payload::encrypted(salt, nonce, ciphertext)
    } else {
        Payload::plaintext(message.as_bytes().to_vec())
    };

    let bytes = payload.to_bytes();
    let capacity_bytes = stego::capacity_bits(&img) / 8;
    if bytes.len() > capacity_bytes {
        return Err(format!(
            "message too large for this image: needs {} bytes, image holds {} bytes. \
             Use a bigger image or a shorter message.",
            bytes.len(),
            capacity_bytes
        ));
    }

    stego::embed(&mut img, &bytes)?;

    img.save_with_format(output, ImageFormat::Png)
        .map_err(|e| format!("failed to write output image: {e}"))?;

    println!(
        "Embedded {} message bytes ({} total with payload header{}) into {} -> {}",
        message.len(),
        bytes.len(),
        if passphrase.is_some() { " + encryption overhead" } else { "" },
        input.display(),
        output.display()
    );
    if passphrase.is_some() {
        println!("Message was encrypted with AES-256-GCM.");
    }
    Ok(())
}

fn run_extract(input: &PathBuf, passphrase: Option<&str>) -> Result<(), String> {
    let img = load_rgba(input)?;
    let raw = stego::extract_all(&img);
    let payload = Payload::from_bytes(&raw)?;

    let message_bytes = if payload.encrypted {
        let pass = passphrase.ok_or_else(|| {
            "this message is encrypted; pass --passphrase to decrypt it".to_string()
        })?;
        crypto::decrypt(&payload.body, pass, &payload.salt.unwrap(), &payload.nonce.unwrap())?
    } else {
        payload.body
    };

    let message = String::from_utf8(message_bytes)
        .map_err(|_| "decoded message is not valid UTF-8".to_string())?;
    println!("{message}");
    Ok(())
}

fn run_capacity(input: &PathBuf) -> Result<(), String> {
    let img = load_rgba(input)?;
    let bits = stego::capacity_bits(&img);
    println!(
        "{}x{} image: {} bits / {} bytes of raw capacity (payload header uses ~9-37 bytes depending on encryption).",
        img.width(),
        img.height(),
        bits,
        bits / 8
    );
    Ok(())
}
