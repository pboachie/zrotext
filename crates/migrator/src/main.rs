// SPDX-License-Identifier: AGPL-3.0-only
use std::{env, path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = run().await {
        eprintln!("migration failed: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut baseline_m0 = false;
    for argument in env::args().skip(1) {
        match argument.as_str() {
            "--baseline-m0" => baseline_m0 = true,
            "--help" | "-h" => {
                println!(
                    "Usage: zrotext-migrator [--baseline-m0]\nReads DATABASE_URL and optional MIGRATIONS_DIR from the environment."
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {argument}; use --help").into()),
        }
    }
    let url = env::var("DATABASE_URL")?;
    let directory = env::var_os("MIGRATIONS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("deploy/compose/migrations"));
    let (mut client, connection) = zrotext_postgres_connection::connect(&url).await?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("database connection ended: {error}");
        }
    });
    let applied = zrotext_migrator::apply(&mut client, &directory, baseline_m0).await?;
    if applied.is_empty() {
        println!("schema is current");
    } else {
        for migration in applied {
            println!(
                "{:03} {} ({})",
                migration.version, migration.filename, migration.kind
            );
        }
    }
    Ok(())
}
