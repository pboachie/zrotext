// SPDX-License-Identifier: AGPL-3.0-only
#[cfg(windows)]
mod windows;

#[cfg(all(windows, test))]
#[path = "../../root-terminal/test-support/native_process.rs"]
mod native_process;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        #[cfg(feature = "unlock")]
        let help = {
            let mut help = String::from(
                "Candidate offline Windows owner tool\ninit --account UUID --origin HTTPS_ORIGIN\nrestore-check --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID\nNo enrollment. Creation requires a separate recovery check.\n",
            );
            // Only a deliberate --features unlock build even lists the command.
            help.push_str(
                "unlock --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID --challenge FILE\nSigns one enrollment challenge after verified recovery (candidate).\n",
            );
            help.push_str("conversation-refresh (explicit unlock build only): independently expected --account --origin --bundle --proposal --output --session --interval --device --line --generation --peer --manifest-version --manifest-digest --phone-reader --archive-reader --signer --signer-point --until, in that order. One typed role-5 manifest refresh; archive records remain exact.\n");
            help
        };
        #[cfg(not(feature = "unlock"))]
        let help = "Candidate offline Windows owner tool\ninit --account UUID --origin HTTPS_ORIGIN\nrestore-check --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID\nNo enrollment. Creation requires a separate recovery check.\n";
        println!("{help}");
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
    // Fixed diagnostics only. Never format arguments, context, errors or secrets.
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("unlock") {
        eprintln!(
            "Operation failed. No signature was produced; the stored bundle and recovery state are unchanged."
        );
        return std::process::ExitCode::FAILURE;
    }
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("conversation-refresh") {
        eprintln!(
            "Operation failed. No usable signed result is confirmed; the stored bundle and recovery state are unchanged. A partial public output may need separate inspection."
        );
        return std::process::ExitCode::FAILURE;
    }
    eprintln!(
        "Operation failed. No recovery readiness is established; any existing bundle remains unchanged."
    );
    std::process::ExitCode::FAILURE
}
