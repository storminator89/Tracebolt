//! Portable counterpart of the original Go window/font placement contract.
//! This is geometry only; it cannot grant consent or admit a host operation.

pub(crate) const WINDOW_STYLE: u32 = 0x00c00000 | 0x00080000 | 0x00040000 | 0x00020000 | 0x00010000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

fn scale(value: i32, dpi: u32) -> i32 {
    (value * dpi as i32 + 48) / 96
}

fn scale_up(value: i32, dpi: u32) -> i32 {
    (value * dpi as i32 + 95) / 96
}

pub(crate) fn font_height(dpi: u32) -> Option<i32> {
    // Original nine-point Segoe UI: 12 design pixels, rounded like Go scale().
    (96..=768).contains(&dpi).then(|| -scale(12, dpi))
}

pub(crate) fn initial_frame(
    work: Frame,
    dpi: u32,
    frame_width: i32,
    frame_height: i32,
) -> Option<Frame> {
    font_height(dpi)?;
    if frame_width < 0 || frame_height < 0 {
        return None;
    }
    let min_width = scale_up(600, dpi).checked_add(frame_width)?;
    let min_height = scale_up(440, dpi).checked_add(frame_height)?;
    if work.width < min_width || work.height < min_height {
        return None;
    }
    let width = scale(840, dpi).checked_add(frame_width)?.min(work.width);
    let height = scale(680, dpi).checked_add(frame_height)?.min(work.height);
    Some(Frame {
        x: work.x.checked_add((work.width - width) / 2)?,
        y: work.y.checked_add((work.height - height) / 2)?,
        width,
        height,
    })
}

pub(crate) fn clamp_frame(
    current: Frame,
    work: Frame,
    dpi: u32,
    frame_width: i32,
    frame_height: i32,
) -> Option<Frame> {
    initial_frame(work, dpi, frame_width, frame_height)?;
    let width = current
        .width
        .clamp(scale_up(600, dpi) + frame_width, work.width);
    let height = current
        .height
        .clamp(scale_up(440, dpi) + frame_height, work.height);
    let right = work.x.checked_add(work.width.checked_sub(width)?)?;
    let bottom = work.y.checked_add(work.height.checked_sub(height)?)?;
    Some(Frame {
        x: current.x.clamp(work.x, right),
        y: current.y.clamp(work.y, bottom),
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn font_is_original_rounded_twelve_dip_not_sixteen() {
        for (dpi, expected) in [
            (96, -12),
            (120, -15),
            (132, -17),
            (144, -18),
            (168, -21),
            (192, -24),
            (240, -30),
            (768, -96),
        ] {
            assert_eq!(font_height(dpi), Some(expected));
        }
        assert_eq!(font_height(95), None);
        assert_eq!(font_height(769), None);
    }

    #[test]
    fn style_has_original_resize_minimize_and_maximize_controls() {
        assert_eq!(WINDOW_STYLE, 0x00cf0000);
        assert_ne!(WINDOW_STYLE & 0x00010000, 0);
    }

    #[test]
    fn settings_change_preserves_current_position_and_size_when_visible() {
        let work = Frame {
            x: -1920,
            y: 40,
            width: 1920,
            height: 1040,
        };
        let current = Frame {
            x: -1630,
            y: 130,
            width: 900,
            height: 740,
        };
        assert_eq!(clamp_frame(current, work, 96, 16, 39), Some(current));
        assert_ne!(initial_frame(work, 96, 16, 39), Some(current));
    }

    #[test]
    fn display_and_dpi_changes_clamp_instead_of_resetting() {
        let work = Frame {
            x: 100,
            y: 50,
            width: 1280,
            height: 900,
        };
        let current = Frame {
            x: 1100,
            y: 700,
            width: 1000,
            height: 800,
        };
        assert_eq!(
            clamp_frame(current, work, 96, 16, 39),
            Some(Frame {
                x: 380,
                y: 150,
                width: 1000,
                height: 800
            })
        );
        let minimum = Frame {
            x: 100,
            y: 50,
            width: 600,
            height: 440,
        };
        assert_eq!(
            clamp_frame(minimum, work, 144, 24, 58),
            Some(Frame {
                x: 100,
                y: 50,
                width: 924,
                height: 718
            })
        );
        assert_eq!(
            initial_frame(Frame { width: 923, ..work }, 144, 24, 58),
            None
        );
    }

    #[test]
    fn initial_placement_remains_centered_and_fits_work_area() {
        let work = Frame {
            x: 100,
            y: 50,
            width: 1280,
            height: 900,
        };
        assert_eq!(
            initial_frame(work, 96, 16, 39),
            Some(Frame {
                x: 312,
                y: 140,
                width: 856,
                height: 719
            })
        );
    }
}
