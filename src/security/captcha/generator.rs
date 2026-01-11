//! CAPTCHA generation logic.
//!
//! Implements image generation with customizable difficulty, visual noise,
//! and coordinate tracking for validation.

use ab_glyph::{FontRef, PxScale};
use base64::{Engine, engine::general_purpose::STANDARD};
use image::{ImageBuffer, Rgb, RgbImage};
use imageproc::drawing::{draw_antialiased_line_segment_mut, draw_text_mut};
use imageproc::geometric_transformations::{Interpolation, rotate_about_center};
use imageproc::pixelops::interpolate;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

const CHARSET: &[u8] = b"ACDEFGHJKLMNPQRSTUVWXYZ2345679";
const IMG_SIZE_U32: u32 = 160;
const IMG_SIZE_F32: f32 = 160.0;
const PASSCODE_LENGTH: usize = 6;
const FONT_BYTES: &[u8] = include_bytes!("../../../assets/Hack-Bold.ttf");

/// Position of a character in the CAPTCHA image.
pub struct CharPosition {
    pub x: f32,
    pub y: f32,
    pub rotation: f32,
}

struct CharDrawParams {
    ch: char,
    x: f32,
    y: f32,
    size: f32,
    rotation_deg: f32,
    color: Rgb<u8>,
}

struct ArcParams {
    cx: i32,
    cy: i32,
    radius: i32,
    start_deg: f32,
    sweep_deg: f32,
    color: Rgb<u8>,
}

/// CAPTCHA difficulty level.
#[derive(Clone, Copy)]
pub enum Difficulty {
    Easy,
    Medium,
    Hard,
}

impl std::str::FromStr for Difficulty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "easy" => Ok(Self::Easy),
            "hard" => Ok(Self::Hard),
            _ => Ok(Self::Medium),
        }
    }
}

impl Difficulty {
    const fn decoy_count(self) -> usize {
        match self {
            Self::Easy => 40,
            Self::Medium => 60,
            Self::Hard => 80,
        }
    }

    const fn arc_count(self) -> usize {
        match self {
            Self::Easy => 20,
            Self::Medium => 30,
            Self::Hard => 40,
        }
    }
}

use crate::config::CaptchaStyle;
use crate::security::crypto::CookieCrypto;

/// Generates AI-resistant image CAPTCHAs.
pub struct CaptchaGenerator {
    cookie_crypto: CookieCrypto,
    ttl_secs: u64,
    difficulty: Difficulty,
    style: CaptchaStyle,
    font: FontRef<'static>,
}

impl CaptchaGenerator {
    /// Creates a new CAPTCHA generator.
    ///
    /// # Panics
    ///
    /// Panics if the embedded font data is invalid or fails to load.
    #[must_use]
    pub fn new(secret: &str, ttl_secs: u64, difficulty: Difficulty, style: CaptchaStyle) -> Self {
        let font = FontRef::try_from_slice(FONT_BYTES).expect("Failed to load embedded font");
        Self {
            cookie_crypto: CookieCrypto::new(secret),
            ttl_secs,
            difficulty,
            style,
            font,
        }
    }

    /// Generates a new CAPTCHA challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated image cannot be encoded as PNG.
    pub fn generate(&self) -> Result<(String, String, Vec<CharPosition>), String> {
        let mut rng = rand::rng();

        let _: String = (0..PASSCODE_LENGTH)
            .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
            .collect();

        let (width, height) = match self.style {
            CaptchaStyle::Complex => (IMG_SIZE_U32, IMG_SIZE_U32),
            CaptchaStyle::Simple => (400, 150),
        };

        let mut img: RgbImage = ImageBuffer::from_fn(width, height, |_, _| Rgb([26, 30, 35]));

        let (colors, line_colors) = Self::generate_colors(&mut rng);

        Self::draw_background(&mut img, &mut rng, self.difficulty, &colors, &line_colors);
        self.draw_decoys(&mut img, &mut rng, &line_colors);

        let (final_passcode, positions) = match self.style {
            CaptchaStyle::Complex => {
                let (char_map, font_size) = self.draw_main_chars(&mut img, &mut rng, &colors);
                Self::select_passcode(&mut rng, char_map, font_size)
            }
            CaptchaStyle::Simple => self.draw_simple_mode(&mut img, &mut rng, &colors),
        };

        let mut webp_data = Vec::new();
        img.write_to(
            &mut std::io::Cursor::new(&mut webp_data),
            image::ImageFormat::WebP,
        )
        .map_err(|e| format!("WebP encode failed: {e}"))?;

        let img_base64 = format!("data:image/webp;base64,{}", STANDARD.encode(&webp_data));

        Ok((final_passcode, img_base64, positions))
    }

    #[must_use]
    pub fn create_token(&self, passcode: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expiry = now + self.ttl_secs;
        let payload = format!("{passcode}|{expiry}");
        self.cookie_crypto.encrypt(payload.as_bytes())
    }

    fn draw_rotated_char(&self, img: &mut RgbImage, params: &CharDrawParams) {
        let scratch_size = f32_to_u32(params.size * 2.0);
        let mut scratch: RgbImage =
            ImageBuffer::from_pixel(scratch_size, scratch_size, Rgb([26, 30, 35]));

        let center_offset = i32::try_from(scratch_size / 4).unwrap_or(0);
        draw_text_mut(
            &mut scratch,
            params.color,
            center_offset,
            center_offset,
            PxScale::from(params.size),
            &self.font,
            &params.ch.to_string(),
        );

        let angle_rad = params.rotation_deg.to_radians();
        let rotated = rotate_about_center(
            &scratch,
            angle_rad,
            Interpolation::Bilinear,
            Rgb([26, 30, 35]),
        );

        let half_scratch = i32::try_from(scratch_size / 2).unwrap_or(0);
        let params_x = f32_to_i32(params.x);
        let params_y = f32_to_i32(params.y);

        let (width, height) = img.dimensions();
        let width_i32 = i32::try_from(width).unwrap_or(160);
        let height_i32 = i32::try_from(height).unwrap_or(160);

        for (rx, ry, pixel) in rotated.enumerate_pixels() {
            if pixel[0] > 30 || pixel[1] > 35 || pixel[2] > 40 {
                let pixel_x = i32::try_from(rx).unwrap_or(0);
                let pixel_y = i32::try_from(ry).unwrap_or(0);
                let gx = params_x + pixel_x - half_scratch;
                let gy = params_y + pixel_y - half_scratch;
                if (0..width_i32).contains(&gx)
                    && (0..height_i32).contains(&gy)
                    && let (Ok(gx_u32), Ok(gy_u32)) = (u32::try_from(gx), u32::try_from(gy))
                {
                    img.put_pixel(gx_u32, gy_u32, *pixel);
                }
            }
        }
    }

    fn draw_arc(img: &mut RgbImage, params: &ArcParams) {
        let steps: i16 = 50;
        let start_rad = params.start_deg.to_radians();
        let sweep_rad = params.sweep_deg.to_radians();

        let radius_f32 = f32::from(i16::try_from(params.radius).unwrap_or(0));
        let mut prev_x = params.cx + f32_to_i32(radius_f32 * start_rad.cos());
        let mut prev_y = params.cy + f32_to_i32(radius_f32 * start_rad.sin());

        for i in 1..=steps {
            let i_f32 = f32::from(i);
            let steps_f32 = f32::from(steps);
            let angle = start_rad + (sweep_rad * i_f32 / steps_f32);
            let curr_x = params.cx + f32_to_i32(radius_f32 * angle.cos());
            let curr_y = params.cy + f32_to_i32(radius_f32 * angle.sin());

            if prev_x >= 0 && prev_y >= 0 && curr_x >= 0 && curr_y >= 0 {
                draw_antialiased_line_segment_mut(
                    img,
                    (prev_x, prev_y),
                    (curr_x, curr_y),
                    params.color,
                    interpolate,
                );
            }

            prev_x = curr_x;
            prev_y = curr_y;
        }
    }

    /// Verifies a CAPTCHA answer using the provided stateless token.
    ///
    #[must_use]
    pub fn verify(&self, token: &str, answer: &str) -> bool {
        let Ok(decrypted) = self.cookie_crypto.decrypt(token).ok_or(()) else {
            return false;
        };
        let Ok(payload) = String::from_utf8(decrypted) else {
            return false;
        };

        let parts: Vec<&str> = payload.split('|').collect();
        if parts.len() != 2 {
            return false;
        }

        let expected_passcode = parts[0];
        let Ok(expiry) = parts[1].parse::<u64>() else {
            return false;
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > expiry {
            return false;
        }

        expected_passcode == answer.to_uppercase().replace([' ', '\n'], "")
    }

    fn generate_colors(rng: &mut impl Rng) -> (Vec<Rgb<u8>>, Vec<Rgb<u8>>) {
        let mut colors: Vec<Rgb<u8>> = Vec::new();
        for _ in 0..4 {
            let mut c = [
                rng.random_range(90..=255),
                rng.random_range(90..=255),
                rng.random_range(90..=255),
            ];
            c[rng.random_range(0..3)] = rng.random_range(180..=255);
            colors.push(Rgb(c));
        }
        let line_colors: Vec<Rgb<u8>> = colors.iter().take(2).copied().collect();
        (colors, line_colors)
    }

    fn draw_background(
        img: &mut RgbImage,
        rng: &mut impl Rng,
        difficulty: Difficulty,
        colors: &[Rgb<u8>],
        line_colors: &[Rgb<u8>],
    ) {
        let (width, height) = img.dimensions();
        let width_i32 = i32::try_from(width).unwrap_or(160);
        let height_i32 = i32::try_from(height).unwrap_or(160);

        for _ in 0..difficulty.arc_count() {
            let color = if rng.random_range(0..100) < 25 {
                colors[rng.random_range(0..colors.len())]
            } else {
                line_colors[rng.random_range(0..line_colors.len())]
            };

            let arc = ArcParams {
                cx: rng.random_range(0..width_i32),
                cy: rng.random_range(0..height_i32),
                radius: rng.random_range(10..80),
                start_deg: rng.random_range(0.0..360.0_f32),
                sweep_deg: rng.random_range(30.0..180.0_f32),
                color,
            };
            Self::draw_arc(img, &arc);
        }
    }

    fn draw_decoys(&self, img: &mut RgbImage, rng: &mut impl Rng, line_colors: &[Rgb<u8>]) {
        let (width, height) = img.dimensions();
        let width_f32 = f32::from(u16::try_from(width).unwrap_or(160));
        let height_f32 = f32::from(u16::try_from(height).unwrap_or(160));

        let fake_font_size = rng.random_range(16.0..28.0);
        for _ in 0..self.difficulty.decoy_count() {
            let params = CharDrawParams {
                ch: CHARSET[rng.random_range(0..CHARSET.len())] as char,
                x: rng.random_range(5.0..(width_f32 - 20.0)),
                y: rng.random_range(5.0..(height_f32 - 20.0)),
                size: fake_font_size,
                rotation_deg: rng.random_range(0.0..360.0),
                color: line_colors[rng.random_range(0..line_colors.len())],
            };
            self.draw_rotated_char(img, &params);
        }
    }

    fn draw_main_chars(
        &self,
        img: &mut RgbImage,
        rng: &mut impl Rng,
        colors: &[Rgb<u8>],
    ) -> (Vec<(String, f32, f32, f32)>, f32) {
        let font_size: f32 = rng.random_range(20.0..26.0);
        let mut char_map: Vec<(String, f32, f32, f32)> = Vec::new();

        let step = font_size.mul_add(1.3, 4.0);
        let max_pos = font_size.mul_add(-1.5, IMG_SIZE_F32);
        for col in 0..20_u16 {
            let col_f32 = f32::from(col);
            let x_base = col_f32.mul_add(step, 4.0);
            if x_base >= max_pos {
                break;
            }

            let x_pos = x_base + rng.random_range(0.0..4.0);

            for row in 0..20_u16 {
                let row_f32 = f32::from(row);

                let y_base = row_f32 * font_size * 1.3;
                if y_base >= max_pos {
                    break;
                }

                let y_pos = y_base + rng.random_range(4.0..12.0);

                let ch = CHARSET[rng.random_range(0..CHARSET.len())] as char;
                let x_buffer = x_pos + rng.random_range(-2.0..6.0);
                let rotation = rng.random_range(0.0..60.0);
                let color = colors[rng.random_range(0..colors.len())];

                let params = CharDrawParams {
                    ch,
                    x: x_buffer,
                    y: y_pos,
                    size: font_size,
                    rotation_deg: rotation,
                    color,
                };
                self.draw_rotated_char(img, &params);
                let params2 = CharDrawParams {
                    ch,
                    x: x_buffer + 1.0,
                    y: y_pos,
                    size: font_size,
                    rotation_deg: rotation,
                    color,
                };
                self.draw_rotated_char(img, &params2);

                char_map.push((ch.to_string(), x_buffer, y_pos, rotation));
            }
        }
        (char_map, font_size)
    }

    fn select_passcode(
        rng: &mut impl Rng,
        char_map: Vec<(String, f32, f32, f32)>,
        font_size: f32,
    ) -> (String, Vec<CharPosition>) {
        let mut final_passcode = String::new();
        let mut positions = Vec::new();
        let margin = 20.0;
        let safe_chars: Vec<_> = char_map
            .into_iter()
            .filter(|(_, x, y, _)| {
                *x >= margin
                    && *x <= (IMG_SIZE_F32 - margin)
                    && *y >= margin
                    && *y <= (IMG_SIZE_F32 - margin)
            })
            .collect();

        let mut available_chars = safe_chars;

        for _ in 0..PASSCODE_LENGTH {
            if available_chars.is_empty() {
                break;
            }
            let idx = rng.random_range(0..available_chars.len());
            let (text, mut x, mut y, rot) = available_chars.remove(idx);
            final_passcode.push_str(&text);

            x -= (9.0 - font_size).mul_add(1.1, font_size);
            y -= (13.0 - font_size).mul_add(1.1, font_size);
            x = x.max(0.0);
            y = y.max(0.0);

            positions.push(CharPosition {
                x,
                y,
                rotation: rot,
            });
        }
        (final_passcode, positions)
    }

    fn draw_simple_mode(
        &self,
        img: &mut RgbImage,
        rng: &mut impl Rng,
        colors: &[Rgb<u8>],
    ) -> (String, Vec<CharPosition>) {
        let mut passcode = String::with_capacity(PASSCODE_LENGTH);
        let mut positions = Vec::with_capacity(PASSCODE_LENGTH);

        let font_size = 40.0;
        let start_x = 40.0;
        let start_y = (150.0 - font_size) / 2.0;

        let max_rot = match self.difficulty {
            Difficulty::Easy => 0.0,
            Difficulty::Medium => 5.0,
            Difficulty::Hard => 15.0,
        };

        for i in 0..PASSCODE_LENGTH {
            let ch = CHARSET[rng.random_range(0..CHARSET.len())] as char;
            passcode.push(ch);

            let x_offset = start_x
                + (f32::from(u16::try_from(i).unwrap_or(0)) * 55.0)
                + rng.random_range(-5.0..5.0);
            let y_offset = start_y + rng.random_range(-5.0..5.0);
            let rotation = if max_rot > 0.0 {
                rng.random_range(-max_rot..max_rot)
            } else {
                0.0
            };

            let params = CharDrawParams {
                ch,
                x: x_offset,
                y: y_offset,
                size: font_size,
                rotation_deg: rotation,
                color: colors[rng.random_range(0..colors.len())],
            };

            self.draw_rotated_char(img, &params);

            positions.push(CharPosition {
                x: x_offset,
                y: y_offset,
                rotation,
            });
        }

        (passcode, positions)
    }
}

#[inline]
fn f32_to_i32(val: f32) -> i32 {
    let clamped = val.round().clamp(f32::from(i16::MIN), f32::from(i16::MAX));
    format!("{clamped:.0}").parse::<i32>().unwrap_or(0)
}

#[inline]
fn f32_to_u32(val: f32) -> u32 {
    let clamped = val.round().clamp(0.0, f32::from(u16::MAX));
    format!("{clamped:.0}").parse::<u32>().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_generator() -> CaptchaGenerator {
        CaptchaGenerator::new("secret", 300, Difficulty::Medium, CaptchaStyle::Simple)
    }

    #[test]
    fn test_difficulty_parsing() {
        assert!(matches!(
            Difficulty::from_str("easy").unwrap(),
            Difficulty::Easy
        ));
        assert!(matches!(
            Difficulty::from_str("hard").unwrap(),
            Difficulty::Hard
        ));
        assert!(matches!(
            Difficulty::from_str("medium").unwrap(),
            Difficulty::Medium
        ));
        assert!(matches!(
            Difficulty::from_str("default").unwrap(),
            Difficulty::Medium
        ));
    }

    #[test]
    fn test_token_creation_and_verification() {
        let generator = create_generator();
        let passcode = "ABCDEF";
        let token = generator.create_token(passcode);

        assert!(generator.verify(&token, "ABCDEF"));
        assert!(generator.verify(&token, "abcdef"));
        assert!(!generator.verify(&token, "WRONG"));
    }

    #[test]
    fn test_token_expiry() {
        let generator =
            CaptchaGenerator::new("secret", 0, Difficulty::Medium, CaptchaStyle::Simple);
        let token = generator.create_token("ABCDEF");

        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!generator.verify(&token, "ABCDEF"));
    }

    #[test]
    fn test_image_generation_format() {
        let generator = create_generator();
        let result = generator.generate();
        assert!(result.is_ok());

        let (passcode, img_base64, positions) = result.unwrap();
        assert_eq!(passcode.len(), PASSCODE_LENGTH);
        assert!(img_base64.starts_with("data:image/webp;base64,"));
        assert_eq!(positions.len(), PASSCODE_LENGTH);
    }

    #[test]
    fn test_coordinate_mapping() {
        let generator = create_generator();
        let (_, _, positions) = generator.generate().unwrap();

        for pos in positions {
            assert!(pos.x >= 0.0);
            assert!(pos.y >= 0.0);
        }
    }

    #[test]
    fn test_difficulty_decoy_counts() {
        assert_eq!(Difficulty::Easy.decoy_count(), 40);
        assert_eq!(Difficulty::Medium.decoy_count(), 60);
        assert_eq!(Difficulty::Hard.decoy_count(), 80);
    }

    #[test]
    fn test_difficulty_arc_counts() {
        assert_eq!(Difficulty::Easy.arc_count(), 20);
        assert_eq!(Difficulty::Medium.arc_count(), 30);
        assert_eq!(Difficulty::Hard.arc_count(), 40);
    }

    #[test]
    fn test_complex_style_generation() {
        let generator =
            CaptchaGenerator::new("secret", 300, Difficulty::Medium, CaptchaStyle::Complex);
        let result = generator.generate();
        assert!(result.is_ok());
        let (passcode, img_base64, positions) = result.unwrap();
        assert_eq!(passcode.len(), PASSCODE_LENGTH);
        assert!(img_base64.starts_with("data:image/webp;base64,"));
        assert_eq!(positions.len(), PASSCODE_LENGTH);
    }

    #[test]
    fn test_hard_difficulty_generation() {
        let generator =
            CaptchaGenerator::new("secret", 300, Difficulty::Hard, CaptchaStyle::Simple);
        let result = generator.generate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_easy_difficulty_generation() {
        let generator =
            CaptchaGenerator::new("secret", 300, Difficulty::Easy, CaptchaStyle::Simple);
        let result = generator.generate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_f32_conversions() {
        assert_eq!(f32_to_i32(10.5), 11);
        assert_eq!(f32_to_i32(-5.3), -5);
        assert_eq!(f32_to_u32(15.8), 16);
        assert_eq!(f32_to_u32(-1.0), 0);
    }
}
