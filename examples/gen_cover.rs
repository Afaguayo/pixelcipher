//! Dev-only helper: generates a small deterministic test PNG at
//! tests/fixtures/cover.png for manual CLI smoke-testing. Not part of
//! the public API or the test suite itself.
fn main() {
    let img = image::RgbaImage::from_fn(300, 300, |x, y| {
        image::Rgba([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8, 255])
    });
    img.save("tests/fixtures/cover.png").unwrap();
    println!("wrote tests/fixtures/cover.png");
}
