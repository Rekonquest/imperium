//! Interactive prompts for the setup wizard

use std::io::{self, Write};

/// Colors for terminal output
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const RED: &str = "\x1b[31m";
}

use colors::*;

/// Print the Cloakwise banner
pub fn print_banner() {
    println!(
        r#"
{CYAN}{BOLD}
   _____ _             _               _
  / ____| |           | |             (_)
 | |    | | ___   __ _| | ____      ___ ___  ___
 | |    | |/ _ \ / _` | |/ /\ \ /\ / / / __|/ _ \
 | |____| | (_) | (_| |   <  \ V  V /| \__ \  __/
  \_____|_|\___/ \__,_|_|\_\  \_/\_/ |_|___/\___|

{RESET}{DIM}  Adaptive VPN Cluster Defense System
  Setup Wizard v0.1.0
{RESET}
"#
    );
}

/// Print a section header
pub fn print_section(title: &str) {
    println!("\n{BLUE}{BOLD}━━━ {} ━━━{RESET}\n", title);
}

/// Print an info message
pub fn print_info(msg: &str) {
    println!("{DIM}ℹ {}{RESET}", msg);
}

/// Print a success message
pub fn print_success(msg: &str) {
    println!("{GREEN}✓ {}{RESET}", msg);
}

/// Print a warning message
pub fn print_warning(msg: &str) {
    println!("{YELLOW}⚠ {}{RESET}", msg);
}

/// Print an error message
pub fn print_error(msg: &str) {
    println!("{RED}✗ {}{RESET}", msg);
}

/// Prompt for yes/no input
pub fn prompt_yes_no(question: &str, default: bool) -> bool {
    let default_hint = if default { "[Y/n]" } else { "[y/N]" };
    print!("{CYAN}?{RESET} {} {DIM}{}{RESET} ", question, default_hint);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_lowercase();

    match input.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        "" => default,
        _ => {
            print_warning("Please enter 'y' or 'n'");
            prompt_yes_no(question, default)
        }
    }
}

/// Prompt for text input
pub fn prompt_text(question: &str, default: Option<&str>) -> String {
    let default_hint = default.map(|d| format!(" {DIM}[{}]{RESET}", d)).unwrap_or_default();
    print!("{CYAN}?{RESET} {}{} ", question, default_hint);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        input.to_string()
    }
}

/// Prompt for numeric input
pub fn prompt_number(question: &str, default: u32, min: u32, max: u32) -> u32 {
    print!(
        "{CYAN}?{RESET} {} {DIM}[{}-{}, default: {}]{RESET} ",
        question, min, max, default
    );
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        return default;
    }

    match input.parse::<u32>() {
        Ok(n) if n >= min && n <= max => n,
        Ok(_) => {
            print_warning(&format!("Please enter a number between {} and {}", min, max));
            prompt_number(question, default, min, max)
        }
        Err(_) => {
            print_warning("Please enter a valid number");
            prompt_number(question, default, min, max)
        }
    }
}

/// Display a menu and get user selection
pub fn prompt_menu(title: &str, options: &[(&str, &str)], default: usize) -> usize {
    println!("\n{CYAN}?{RESET} {}\n", title);

    for (i, (name, desc)) in options.iter().enumerate() {
        let marker = if i == default { "●" } else { "○" };
        println!(
            "  {CYAN}{}{RESET} {}) {BOLD}{}{RESET} - {DIM}{}{RESET}",
            marker,
            i + 1,
            name,
            desc
        );
    }

    print!("\n  {DIM}Enter choice [1-{}, default: {}]:{RESET} ", options.len(), default + 1);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        return default;
    }

    match input.parse::<usize>() {
        Ok(n) if n >= 1 && n <= options.len() => n - 1,
        _ => {
            print_warning(&format!("Please enter a number between 1 and {}", options.len()));
            prompt_menu(title, options, default)
        }
    }
}

/// Display a multi-select menu
pub fn prompt_multi_select(title: &str, options: &[(&str, &str, bool)]) -> Vec<usize> {
    println!("\n{CYAN}?{RESET} {}", title);
    println!("{DIM}  (Enter numbers separated by commas, or 'all'/'none'){RESET}\n");

    for (i, (name, desc, default)) in options.iter().enumerate() {
        let marker = if *default { "☑" } else { "☐" };
        println!(
            "  {GREEN}{}{RESET} {}) {BOLD}{}{RESET} - {DIM}{}{RESET}",
            marker,
            i + 1,
            name,
            desc
        );
    }

    // Show defaults
    let defaults: Vec<usize> = options
        .iter()
        .enumerate()
        .filter(|(_, (_, _, d))| *d)
        .map(|(i, _)| i + 1)
        .collect();
    let default_str = if defaults.is_empty() {
        "none".to_string()
    } else {
        defaults.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",")
    };

    print!("\n  {DIM}Enter choices [default: {}]:{RESET} ", default_str);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        return options
            .iter()
            .enumerate()
            .filter(|(_, (_, _, d))| *d)
            .map(|(i, _)| i)
            .collect();
    }

    if input == "all" {
        return (0..options.len()).collect();
    }

    if input == "none" {
        return vec![];
    }

    input
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= options.len())
        .map(|n| n - 1)
        .collect()
}

/// Display a progress indicator
pub fn print_progress(current: usize, total: usize, message: &str) {
    let percentage = (current as f64 / total as f64 * 100.0) as usize;
    let filled = percentage / 5;
    let empty = 20 - filled;

    print!(
        "\r{CYAN}[{}{}]{RESET} {}% {}",
        "█".repeat(filled),
        "░".repeat(empty),
        percentage,
        message
    );
    io::stdout().flush().unwrap();

    if current == total {
        println!();
    }
}

/// Wait for user to press Enter
pub fn wait_for_enter(message: &str) {
    print!("\n{DIM}{} (Press Enter to continue){RESET}", message);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

/// Clear the terminal screen
pub fn clear_screen() {
    print!("\x1b[2J\x1b[H");
    io::stdout().flush().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colors_defined() {
        assert!(!RESET.is_empty());
        assert!(!BOLD.is_empty());
        assert!(!GREEN.is_empty());
    }
}
