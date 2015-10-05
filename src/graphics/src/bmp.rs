use common::string::*;
use common::vec::*;

use graphics::color::*;
use graphics::display::*;
use graphics::point::*;
use graphics::size::*;

pub struct BMP {
    pub data: Vec<u32>,
    pub size: Size,
}

impl BMP {
    pub fn new() -> BMP {
        BMP {
            data: Vec::new(),
            size: Size {
                width: 0,
                height: 0,
            },
        }
    }

    pub fn from_data(file_data: &Vec<u8>) -> BMP {
        let mut ret = BMP::new();

        let get = |i: usize| -> u8 {
            match file_data.get(i) {
                Option::Some(byte) => *byte,
                Option::None => 0,
            }
        };

        let getw = |i: usize| -> u16 { (get(i) as u16) + ((get(i + 1) as u16) << 8) };

        let getd = |i: usize| -> u32 {
            (get(i) as u32) + ((get(i + 1) as u32) << 8) + ((get(i + 2) as u32) << 16) +
            ((get(i + 3) as u32) << 24)
        };

        let gets = |start: usize, len: usize| -> String {
            let mut ret = String::new();
            for i in start..start + len {
                ret = ret + get(i) as char;
            }
            ret
        };

        if gets(0, 2) == "BM".to_string() {
            let file_size = getd(2);
            let offset = getd(0xA);
            let header_size = getd(0xE);
            let width = getd(0x12);
            let height = getd(0x16);
            let depth = getw(0x1C) as u32;

            let bytes = (depth + 7) / 8;
            let row_bytes = (depth * width + 31) / 32 * 4;

            let mut red_mask = 0xFF0000;
            let mut green_mask = 0xFF00;
            let mut blue_mask = 0xFF;
            let mut alpha_mask = 0xFF000000;
            if getd(0x1E) == 3 {
                red_mask = getd(0x36);
                green_mask = getd(0x3A);
                blue_mask = getd(0x3E);
                alpha_mask = getd(0x42);
            }

            let mut red_shift = 0;
            while red_mask > 0 && red_shift < 32 && (red_mask >> red_shift) & 1 == 0 {
                red_shift += 1;
            }

            let mut green_shift = 0;
            while green_mask > 0 && green_shift < 32 && (green_mask >> green_shift) & 1 == 0 {
                green_shift += 1;
            }

            let mut blue_shift = 0;
            while blue_mask > 0 && blue_shift < 32 && (blue_mask >> blue_shift) & 1 == 0 {
                blue_shift += 1;
            }

            let mut alpha_shift = 0;
            while alpha_mask > 0 && alpha_shift < 32 && (alpha_mask >> alpha_shift) & 1 == 0 {
                alpha_shift += 1;
            }

            ret.size = Size {
                width: width as usize,
                height: height as usize,
            };
            for y in 0..height {
                for x in 0..width {
                    let pixel_offset = offset + (height - y - 1) * row_bytes + x * bytes;

                    let pixel_data = getd(pixel_offset as usize);
                    let red = ((pixel_data & red_mask) >> red_shift) as u8;
                    let green = ((pixel_data & green_mask) >> green_shift) as u8;
                    let blue = ((pixel_data & blue_mask) >> blue_shift) as u8;
                    let alpha = ((pixel_data & alpha_mask) >> alpha_shift) as u8;
                    if bytes == 3 {
                        ret.data.push(Color::new(red, green, blue).data);
                    } else if bytes == 4 {
                        ret.data.push(Color::alpha(red, green, blue, alpha).data);
                    }
                }
            }
        }

        ret
    }

    pub fn draw(&self, display: &Display, point: Point) {
        unsafe {
            display.image_alpha(point, self.data.as_ptr(), self.size);
        }
    }
}
