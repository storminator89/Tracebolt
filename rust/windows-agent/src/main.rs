use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracebolt_windows_agent::{
    config::tls_builder,
    config::{Config, EnrollmentMode, read_bounded},
    enrollment::{Enrollment, validate_initial_bootstrap},
    enrollment_wire::Bootstrap,
};

#[derive(Parser)]
#[command(version, about = "Tracebolt basic Windows telemetry service (Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Validate public installer inputs without creating files, keys or enrollment state.
    ValidateConfig {
        /// Also require a matching manager over the selected TLS trust.
        #[arg(long)]
        check_manager: bool,
        #[arg(long)]
        manager_origin: String,
        #[arg(long, default_value = "")]
        agent_origin: String,
        #[arg(long, default_value = "")]
        agent_id: String,
        #[arg(long, default_value = "auto")]
        mode: String,
        #[arg(long, default_value_t = 60)]
        interval_seconds: u64,
        #[arg(long)]
        server_ca_file: Option<PathBuf>,
        /// Public invitation bootstrap; required only for invitation mode.
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Validate protected configuration and credentials without sending data.
    Check {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Read bounded local health without opening enrollment or sender state.
    Status {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print only allowlisted public support metadata; no raw files or archive.
    SupportBundle {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Create a new ledger for a fresh, approved, never-used endpoint identity.
    Init {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        bootstrap: Option<PathBuf>,
    },
    /// Advance automatic onboarding by one bounded phase without collecting metrics.
    Onboard {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Optional invitation entry, hidden local terminal input; no token in arguments.
    ClaimInvitation {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Collect and send one report; print no telemetry or credentials.
    Once {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        no_health_diagnostics: bool,
    },
    /// Windows Service Control Manager entry point.
    Service {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        no_health_diagnostics: bool,
    },
}

fn main() {
    if let Err(error) = run() {
        if let Some(error) =
            error.downcast_ref::<tracebolt_windows_agent::compatibility::PreflightError>()
        {
            eprintln!("{error}");
        } else {
            eprintln!(
                "Tracebolt operation failed. Check protected configuration, certificate approval, state and server availability. State was not reset."
            );
        }
        std::process::exit(1);
    }
}
fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateConfig {
            check_manager,
            manager_origin,
            agent_origin,
            agent_id,
            mode,
            interval_seconds,
            server_ca_file,
            bootstrap,
        } => {
            let enrollment_mode: EnrollmentMode =
                serde_json::from_value(serde_json::Value::String(mode))?;
            let config = Config {
                schema_version: "tracebolt.rust-windows-basic.v1".into(),
                manager_origin,
                agent_origin,
                agent_id,
                enrollment_mode,
                interval_seconds,
                basic_metrics_acknowledged: true,
            };
            config.validate()?;
            let bootstrap: Option<Bootstrap> = bootstrap
                .map(|p| -> anyhow::Result<_> {
                    Ok(serde_json::from_slice(&read_bounded(&p, 65536)?)?)
                })
                .transpose()?;
            validate_initial_bootstrap(&config, bootstrap.as_ref())?;
            let ca = server_ca_file
                .map(|p| read_bounded(&p, 32768))
                .transpose()?
                .unwrap_or_default();
            tls_builder(&ca)?.build()?;
            if check_manager {
                tracebolt_windows_agent::compatibility::check(&config, &ca)?;
                println!(
                    "Manager protocol compatible at this check; no files or identity created. Enrollment, approval and accepted telemetry not tested."
                );
            } else {
                println!(
                    "Public configuration and CA valid; no files or identity created. Manager connectivity and approval not tested."
                );
            }
        }
        Command::Init {
            directory,
            bootstrap,
        } => {
            let config = Config::load(&directory)?;
            let bootstrap: Option<Bootstrap> = bootstrap
                .map(|p| -> anyhow::Result<_> {
                    Ok(serde_json::from_slice(&read_bounded(&p, 65536)?)?)
                })
                .transpose()?;
            validate_initial_bootstrap(&config, bootstrap.as_ref())?;
            // Recheck fresh enrollment before any ledger, not just in the
            // installer. Advanced preprovided mode keeps its distinct legacy
            // telemetry-origin behavior and is outside this capability contract.
            if config.enrollment_mode != EnrollmentMode::Preprovided {
                tracebolt_windows_agent::compatibility::check(
                    &config,
                    &tracebolt_windows_agent::config::read_ca(&directory)?,
                )?;
            }
            if config.enrollment_mode == EnrollmentMode::Preprovided {
                tracebolt_windows_agent::sender::Sender::open(&directory, true)?;
                println!("Fresh sender state initialized.");
            } else {
                let enrollment = Enrollment::open(&directory, true, bootstrap)?;
                println!("{}", enrollment.public_status()?);
            }
        }
        Command::Onboard { directory } => {
            let mut enrollment = Enrollment::open(&directory, false, None)?;
            enrollment.step(None)?;
            println!("{}", enrollment.public_status()?);
        }
        Command::ClaimInvitation { directory } => {
            let mut enrollment = Enrollment::open(&directory, false, None)?;
            anyhow::ensure!(
                enrollment.config.enrollment_mode == EnrollmentMode::Invitation,
                "invitation mode is optional and must be selected at installation"
            );
            let secret = rpassword::prompt_password("Optional invitation token (hidden): ")?;
            enrollment.step(Some(&secret))?;
            println!("{}", enrollment.public_status()?);
        }
        Command::Check { directory } => {
            tracebolt_windows_agent::runtime::Runtime::open(&directory)?;
            println!("Local configuration and sender state valid; server connectivity not tested.");
        }
        Command::Status { directory, json } => {
            let status = tracebolt_windows_agent::health::status(&directory, chrono::Utc::now());
            if json {
                println!("{}", serde_json::to_string(&status)?);
            } else {
                println!("{}: {}", status.state, status.next_action);
            }
        }
        Command::SupportBundle { directory } => {
            let bytes =
                tracebolt_windows_agent::health::support_bundle(&directory, chrono::Utc::now())?;
            println!("{}", std::str::from_utf8(&bytes)?);
        }
        Command::Once {
            directory,
            no_health_diagnostics,
        } => {
            #[cfg(windows)]
            {
                let mut runtime = if no_health_diagnostics {
                    tracebolt_windows_agent::runtime::Runtime::open_without_health(&directory)?
                } else {
                    tracebolt_windows_agent::runtime::Runtime::open(&directory)?
                };
                if runtime.cycle(tracebolt_windows_agent::native::collect)? {
                    println!("Server acknowledged the report.");
                } else {
                    println!("Onboarding pending manager approval; no report sent.");
                }
            }
            #[cfg(not(windows))]
            {
                let _ = (directory, no_health_diagnostics);
                anyhow::bail!("Windows is required for collection");
            }
        }
        Command::Service {
            directory,
            no_health_diagnostics,
        } => {
            #[cfg(windows)]
            if no_health_diagnostics {
                tracebolt_windows_agent::service::dispatch_without_health(directory)?;
            } else {
                tracebolt_windows_agent::service::dispatch(directory)?;
            }
            #[cfg(not(windows))]
            {
                let _ = (directory, no_health_diagnostics);
                anyhow::bail!("Windows SCM required");
            }
        }
    }
    Ok(())
}
