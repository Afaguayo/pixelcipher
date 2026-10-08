//! Least-significant-bit steganography over an RGBA image: one bit of
//! payload per color channel (R, G, B -- alpha is left untouched so
//! transparency is preserved exactly).

use image::RgbaImage;

/// How many payload bits this image can hold (3 bits per pixel: R, G, B).
pub fn capacity_bits(img: &RgbaImage) -> usize {
    (img.width() as usize) * (img.height() as usize) * 3
}

/// Embeds `payload` into the LSBs of `img`'s R/G/B channels, in place.
/// Returns an error if the image doesn't have enough pixels to hold it.
pub fn embed(img: &mut RgbaImage, payload: &[u8]) -> Result<(), String> {
    let needed_bits = payload.len() * 8;
    let available_bits = capacity_bits(img);
    if needed_bits > available_bits {
        return Err(format!(
            "message too large: needs {} bits but image only has room for {} bits ({} bytes). \
             Use a larger image or a shorter message.",
            needed_bits,
            available_bits,
            available_bits / 8
        ));
    }

    let mut bit_iter = BitReader::new(payload);
    'outer: for pixel in img.pixels_mut() {
        for channel in 0..3 {
            match bit_iter.next() {
                Some(bit) => {
                    pixel[channel] = (pixel[channel] & 0xFE) | bit;
                }
                None => break 'outer,
            }
        }
    }
    Ok(())
}

/// Extracts every embedded bit from `img`'s R/G/B channels and returns the
/// raw byte buffer. The caller (payload::Payload::from_bytes) is
/// responsible for deciding how many of those bytes are meaningful.
pub fn extract_all(img: &RgbaImage) -> Vec<u8> {
    let total_bits = capacity_bits(img);
    let mut bits = Vec::with_capacity(total_bits);
    for pixel in img.pixels() {
        for channel in 0..3 {
            bits.push(pixel[channel] & 1);
        }
    }
    bits_to_bytes(&bits)
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_idx: usize,
    bit_idx: u8, // 0 = MSB
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, byte_idx: 0, bit_idx: 0 }
    }
}

impl Iterator for BitReader<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        if self.byte_idx >= self.data.len() {
            return None;
        }
        let byte = self.data[self.byte_idx];
        let bit = (byte >> (7 - self.bit_idx)) & 1;
        self.bit_idx += 1;
        if self.bit_idx == 8 {
            self.bit_idx = 0;
            self.byte_idx += 1;
        }
        Some(bit)
    }
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 {
            break;
        }
        let mut byte = 0u8;
        for &b in chunk {
            byte = (byte << 1) | b;
        }
        out.push(byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    fn blank_image(w: u32, h: u32) -> RgbaImage {
        RgbaImage::from_pixel(w, h, Rgba([128, 128, 128, 255]))
    }

    #[test]
    fn embed_and_extract_round_trips_small_message() {
        let mut img = blank_image(20, 20); // 20*20*3 = 1200 bits = 150 bytes capacity
        let message = b"PXC1\x00\x05\x00\x00\x00hello"; // doesn't need to be valid payload for this test
        embed(&mut img, message).unwrap();
        let extracted = extract_all(&img);
        assert_eq!(&extracted[..message.len()], message);
    }

    #[test]
    fn rejects_message_too_large_for_image() {
        let mut img = blank_image(4, 4); // 4*4*3 = 48 bits = 6 bytes capacity
        let message = vec![0u8; 100];
        let result = embed(&mut img, &message);
        assert!(result.is_err());
    }

    #[test]
    fn preserves_alpha_channel() {
        let mut img = RgbaImage::from_pixel(10, 10, Rgba([0, 0, 0, 200]));
        let message = b"hi";
        embed(&mut img, message).unwrap();
        for pixel in img.pixels() {
            assert_eq!(pixel[3], 200, "alpha channel must be untouched");
        }
    }

    #[test]
    fn capacity_bits_matches_formula() {
        let img = blank_image(10, 5);
        assert_eq!(capacity_bits(&img), 10 * 5 * 3);
    }

    #[test]
    fn bit_reader_reads_msb_first() {
        let data = [0b1010_0000u8];
        let bits: Vec<u8> = BitReader::new(&data).take(4).collect();
        assert_eq!(bits, vec![1, 0, 1, 0]);
    }
}
