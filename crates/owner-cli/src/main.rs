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
            help.push_str("custody-sign --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID --challenge FILE\nExplicitly authorizes the exact local encrypted custody publication after independent fingerprint comparison and recovery; outputs enrollment and custody signatures only.\n");
            help.push_str("line-key-registration (explicit unlock build only): independently expected --account --origin --root-fingerprint --bundle --proposal --output --user --session --device --line --generation --challenge --nonce --issued --expires --approval-fingerprint --paired-signing-fingerprint --connection-epoch --deployment-epoch --site --instance, in that order. Exact dedicated RootLineRegister transcript only.\n");
            help.push_str("archive-init --account UUID --origin HTTPS_ORIGIN --bundle PUBLIC_ID --archive-output FILE --receipt-output FILE --recovery-output FILE\nExplicit archive creation with authenticated root recovery, separate protected raw32 recovery-file consent and verified create-new publication.\n");
            help.push_str("conversation-genesis (explicit unlock build only): independently expected --account --origin --bundle --proposal --output --session --device --line --device-signing-fingerprint --generation --peer --phone-reader-point --archive-reader-point --phone-signer-point --issued --expires, in that order. First four-role manifest only; requires independent public point comparison.\n");
            help.push_str("conversation-activation (explicit unlock build only): --account --origin --bundle --proposal --output --session --device --line --generation --peer --manifest-version --manifest-digest --phone-reader --archive-reader --phone-signer --issued, in that order. Preserved-record successor only; no root-signed peer/session consent or network activation.\n");
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
    if args.first().map(String::as_str) == Some("archive-init") {
        eprintln!(
            "Operation failed. No completed archive publication is confirmed; selected outputs may remain, including a protected private recovery file. Inspect them separately before retrying. The root bundle is unchanged."
        );
        return std::process::ExitCode::FAILURE;
    }
    #[cfg(feature = "unlock")]
    if args.first().map(String::as_str) == Some("unlock") {
        eprintln!(
            "Operation failed. No signature was produced; the stored bundle and recovery state are unchanged."
        );
        return std::process::ExitCode::FAILURE;
    }
    #[cfg(feature = "unlock")]
    if matches!(
        args.first().map(String::as_str),
        Some(
            "line-key-registration"
                | "conversation-refresh"
                | "conversation-activation"
                | "custody-sign"
                | "conversation-genesis"
        )
    ) {
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
