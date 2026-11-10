//! The name in large letters with a padlock, drawn on the home screen and at
//! the top of every run's screen. In a UTF-8 terminal 81 columns wide or more,
//! the name is in block letters with the padlock standing in for its O.
//! Elsewhere, and in narrower windows, it's in ASCII beside the padlock, and in
//! the narrowest it's left out. It shades from green to red down the rows,
//! padlock and all.

/// The name's first seven letters in block letters, ENCRYPT.
const ENCRYPT: [&str; 6] = [
    "███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗",
    "██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝",
    "█████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ",
    "██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ",
    "███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ",
    "╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ",
];

/// Its last R.
const R: [&str; 6] = ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"];

/// The ASCII art, for terminals that can't show block letters and windows
/// too narrow for them: the padlock beside the name, as figlet's standard
/// font draws it. Its padlock is also the block letters' O.
const ASCII: [&str; 7] = [
    r"   .----.",
    r"  / .--. \                                      _",
    r"  | |  | |      ___ _ __   ___ _ __ _   _ _ __ | |_ ___  _ __",
    r" .'-'--'-'.    / _ \ '_ \ / __| '__| | | | '_ \| __/ _ \| '__|",
    r" |  (  )  |   |  __/ | | | (__| |  | |_| | |_) | || (_) | |",
    r" |   ||   |    \___|_| |_|\___|_|   \__, | .__/ \__\___/|_|",
    r" '--------'                         |___/|_|",
];

/// Columns of each ASCII row the padlock takes, with the gap after it.
const ASCII_LOCK: usize = 13;

/// Columns the padlock takes as the O: every row of it starts with a space,
/// so the first column is left out, the same for every row.
const LOCK_AS_O: usize = 10;

/// Colours for the rows, top to bottom, from the 256-colour palette: green,
/// through yellow and orange, to red, one for each of the art's 7 rows.
const GRADIENT: [u8; 7] = [46, 118, 190, 226, 214, 202, 196];

/// A part of the art, coloured as one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Part {
    Lock,
    Name,
}

/// A row of the art, as the parts it's made of.
pub type Row = Vec<(Part, String)>;

/// What the terminal can draw.
#[derive(Clone, Copy)]
pub struct Look {
    pub utf8: bool,
    pub colors: Colors,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Colors {
    /// Bold only, as NO_COLOR asks.
    None,
    /// The eight standard colours.
    Basic,
    /// 256 colours, for the gradient.
    Rich,
}

impl Look {
    /// From the locale (LC_ALL, LC_CTYPE or LANG, the first that's set), TERM
    /// and COLORTERM, and NO_COLOR.
    pub fn detect() -> Self {
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        let locale = ["LC_ALL", "LC_CTYPE", "LANG"].into_iter().map(var).find(|value| !value.is_empty());
        let locale = locale.unwrap_or_default().to_ascii_lowercase();
        let colors = if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
            Colors::None
        } else if !var("COLORTERM").is_empty() || var("TERM").contains("256color") {
            Colors::Rich
        } else {
            Colors::Basic
        };
        Self { utf8: locale.contains("utf-8") || locale.contains("utf8"), colors }
    }
}

/// The art for a window `cols` wide, each row as its parts: the widest
/// layout that fits, or none.
pub fn rows(cols: usize, utf8: bool) -> Vec<Row> {
    // Each ASCII row as the padlock's part and the name's.
    let split = |i: usize| {
        let line = ASCII[i];
        let at = line.char_indices().nth(ASCII_LOCK).map_or(line.len(), |(at, _)| at);
        (&line[..at], &line[at..])
    };
    let ascii: Vec<Row> = (0..ASCII.len())
        .map(|i| {
            let (lock, name) = split(i);
            vec![(Part::Lock, lock.to_string()), (Part::Name, name.to_string())]
        })
        .collect();
    // The padlock where the O was, with its shackle rising above the letters
    // and a space before the R.
    let lock = |i: usize| format!("{:<LOCK_AS_O$}", split(i).0.get(1..).unwrap_or_default().trim_end());
    let block: Vec<Row> = (0..ASCII.len())
        .map(|i| match i.checked_sub(1) {
            Some(n) => vec![(Part::Name, ENCRYPT[n].to_string()), (Part::Lock, lock(i)), (Part::Name, format!(" {}", R[n]))],
            None => vec![(Part::Name, " ".repeat(ENCRYPT[0].chars().count())), (Part::Lock, lock(i))],
        })
        .collect();
    let layouts = match utf8 {
        true => vec![block, ascii],
        false => vec![ascii],
    };
    layouts.into_iter().find(|rows| rows.iter().all(|row| width(row) <= cols)).unwrap_or_default()
}

/// Columns a row takes.
pub fn width(row: &Row) -> usize {
    row.iter().map(|(_, text)| text.chars().count()).sum()
}

/// Row `i` of `count`, ready to print in `colors`, with the colours reset
/// after it. The whole row is one shade of the gradient.
pub fn paint(row: &Row, i: usize, count: usize, colors: Colors) -> String {
    let style = match colors {
        Colors::None => "1".to_string(),
        // Too few colours to shade: green above, red below.
        Colors::Basic => if i * 2 < count { "1;32" } else { "1;31" }.into(),
        Colors::Rich => format!("1;38;5;{}", GRADIENT[i * (GRADIENT.len() - 1) / count.saturating_sub(1).max(1)]),
    };
    let text: String = row.iter().map(|(_, text)| text.as_str()).collect();
    format!("\x1b[{style}m{text}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(rows: &[Row]) -> Vec<String> {
        rows.iter().map(|row| row.iter().map(|(_, text)| text.as_str()).collect::<String>().trim_end().to_string()).collect()
    }

    #[test]
    fn keeps_each_glyph_square() {
        for glyph in [&ENCRYPT[..], &R] {
            let widths: Vec<usize> = glyph.iter().map(|row| row.chars().count()).collect();
            assert!(widths.iter().all(|&w| w == widths[0]), "{widths:?}");
        }
    }

    #[test]
    fn puts_the_padlock_where_the_o_was_as_it_is() {
        let block = rows(79, true);
        for (i, row) in block.iter().enumerate() {
            let lock = row.iter().find(|(part, _)| *part == Part::Lock).map(|(_, text)| text.trim_end()).unwrap();
            let ascii = ASCII[i].chars().take(ASCII_LOCK).collect::<String>();
            assert_eq!(lock, &ascii.trim_end()[1..], "row {i}");
        }
    }

    #[test]
    fn uses_the_widest_layout_that_fits() {
        let block = rows(79, true);
        assert_eq!(block.iter().map(width).max(), Some(79));
        assert_eq!(text(&block)[0].trim_start(), ".----.", "the shackle rises above the letters");
        assert!(text(&block)[3].ends_with("   ██║   .'-'--'-'. ██████╔╝"), "{:?}", text(&block)[3]);
        assert!(text(&block)[6].ends_with("'--------' ╚═╝  ╚═╝"), "a space before the R on every row");
        assert_eq!(block[3][1], (Part::Lock, ".'-'--'-'.".to_string()));

        let ascii = rows(78, true);
        assert_eq!(ascii.len(), 7);
        assert!(text(&ascii)[2].contains("___ _ __   ___"));
        assert!(text(&rows(200, false)).iter().all(|row| row.is_ascii()), "ASCII without UTF-8, however wide");
        assert!(rows(60, true).is_empty() && rows(60, false).is_empty(), "nothing in the narrowest");
    }

    #[test]
    fn shades_the_padlock_with_the_name() {
        let rows = rows(79, true);
        let second = paint(&rows[1], 1, rows.len(), Colors::Rich);
        let bottom = paint(&rows[6], 6, rows.len(), Colors::Rich);
        assert!(second.starts_with("\x1b[1;38;5;118m███████╗") && second.contains("╗ / .--. \\  ██████╗"), "{second:?}");
        assert_eq!(second.matches("\x1b[").count(), 2, "one shade for the row, then the reset");
        assert!(bottom.starts_with("\x1b[1;38;5;196m") && bottom.ends_with("\x1b[0m"), "{bottom:?}");
        assert!(paint(&rows[0], 0, rows.len(), Colors::Rich).starts_with("\x1b[1;38;5;46m"), "green at the top");
        let whole: String = rows[1].iter().map(|(_, text)| text.as_str()).collect();
        assert_eq!(paint(&rows[1], 1, rows.len(), Colors::None), format!("\x1b[1m{whole}\x1b[0m"), "bold only");
        assert!(paint(&rows[1], 1, rows.len(), Colors::Basic).starts_with("\x1b[1;32m"));
        assert!(paint(&rows[6], 6, rows.len(), Colors::Basic).starts_with("\x1b[1;31m"));
    }
}
