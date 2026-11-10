use anyhow::Result;
use std::path::PathBuf;

pub(crate) struct InitCommandArgs {
    pub initializer: Option<String>,
    pub args: Vec<String>,
    pub yes: bool,
    pub scope: Option<String>,
    pub registry: Option<String>,
    pub cache: Option<PathBuf>,
    pub offline: bool,
}

pub(crate) async fn run(args: InitCommandArgs, current_dir: PathBuf) -> Result<()> {
    if let Some(init_pkg) = args.initializer {
        let transformed = crate::init::transform_initializer(&init_pkg);
        crate::execute_exec(
            &current_dir,
            &transformed,
            &[],
            &args.args,
            args.registry,
            args.cache,
            args.offline,
        )
        .await?;
    } else {
        let init_opts = crate::init::InitOptions {
            yes: args.yes,
            scope: args.scope,
            directory: current_dir,
        };
        let stdin = std::io::stdin();
        let mut stdin_lock = stdin.lock();
        let stdout = std::io::stdout();
        let mut stdout_lock = stdout.lock();
        crate::init::run_init(&init_opts, &mut stdin_lock, &mut stdout_lock)?;
    }
    Ok(())
}
