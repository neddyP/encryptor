//! The report printed when a command succeeds.

pub fn print_report(title: &str, rows: &[(&str, String)]) {
    let rule = "-".repeat(64);
    println!("\n{rule}\n  {title}\n{rule}");
    for (label, value) in rows {
        println!("  {label:<14} {value}");
    }
    println!("{rule}");
}

pub fn fmt_size(bytes: usize) -> String {
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    let mut value = bytes as f64;
    let mut unit = "";
    for u in ["KiB", "MiB", "GiB", "TiB"] {
        value /= 1024.0;
        unit = u;
        if value < 1024.0 {
            break;
        }
    }
    format!("{bytes} bytes ({value:.1} {unit})")
}
