//! Remote command execution over a russh exec channel (no `ssh` binary).

use std::io::Write as _;
use std::sync::Arc;

use russh::ChannelMsg;

use crate::domain::errors::ExecError;
use crate::domain::models::{CommandOutput, OutputMode, Remote, RemoteCommand};
use crate::domain::ports::{PortFuture, RemoteExecutor};
use crate::outbound::ssh::SshPool;

/// Runs remote commands over a pooled pure-Rust russh session.
#[derive(Clone)]
pub struct SshExecutor {
    pool: Arc<SshPool>,
}

impl SshExecutor {
    pub fn new(pool: Arc<SshPool>) -> Self {
        Self { pool }
    }
}

impl RemoteExecutor for SshExecutor {
    fn run<'a>(
        &'a self,
        remote: &'a Remote,
        command: &'a RemoteCommand,
        output: OutputMode,
    ) -> PortFuture<'a, Result<CommandOutput, ExecError>> {
        Box::pin(async move {
            let conn = self.pool.connect(remote).await?;
            // Hold the connection lock only to open the channel; release it before the build runs.
            let mut channel = {
                let handle = conn.lock().await;
                handle
                    .channel_open_session()
                    .await
                    .map_err(|e| ExecError::Ssh(e.into()))?
            };
            channel
                .exec(true, command.line.as_bytes())
                .await
                .map_err(|e| ExecError::Ssh(e.into()))?;

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut exit_code = None;

            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { ref data } => sink(output, false, data, &mut stdout),
                    ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                        sink(output, true, data, &mut stderr)
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status as i32),
                    ChannelMsg::ExitSignal {
                        signal_name,
                        error_message,
                        ..
                    } => {
                        tracing::warn!(
                            signal = ?signal_name,
                            message = %error_message,
                            "remote command terminated by signal"
                        );
                        // Convention: signal termination → 128 + n; we lack n, so use 128.
                        exit_code = Some(128);
                    }
                    _ => {}
                }
            }

            Ok(CommandOutput {
                exit_code: exit_code.ok_or(ExecError::NoExitStatus)?,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            })
        })
    }
}

/// Stream a chunk live (Inherit) or collect it (Capture).
fn sink(mode: OutputMode, is_stderr: bool, data: &[u8], buffer: &mut Vec<u8>) {
    match mode {
        OutputMode::Capture => buffer.extend_from_slice(data),
        OutputMode::Inherit => {
            if is_stderr {
                let _ = std::io::stderr().write_all(data);
                let _ = std::io::stderr().flush();
            } else {
                let _ = std::io::stdout().write_all(data);
                let _ = std::io::stdout().flush();
            }
        }
    }
}
