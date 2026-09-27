// SPDX-License-Identifier: AGPL-3.0-only
#[cfg(windows)]
mod windows;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "Candidate offline Windows owner tool\ninit --account UUID --origin HTTPS_ORIGIN\nrestore-check --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID\nNo enrollment. Creation requires a separate recovery check."
        );
        return std::process::ExitCode::SUCCESS;
    }
    if args == ["--version"] {
        println!("zrotext-owner {} (candidate)", env!("CARGO_PKG_VERSION"));
        return std::process::ExitCode::SUCCESS;
    }
    #[cfg(windows)]
    if windows::run(&args).is_ok() {
        return std::process::ExitCode::SUCCESS;
    }
    // Fixed diagnostic only. Never format arguments, context, errors or secrets.
    eprintln!(
        "Operation failed. No recovery readiness is established; any existing bundle remains unchanged."
    );
    std::process::ExitCode::FAILURE
}
