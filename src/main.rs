use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    aduana::cli::run(&args)
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_version_is_set() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
