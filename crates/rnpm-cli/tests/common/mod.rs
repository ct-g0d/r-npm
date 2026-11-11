use std::process::Command;

#[allow(dead_code)]
pub fn isolated_npm() -> Command {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/d", "/s", "/c", "npm.cmd"]);
        cmd
    }
    #[cfg(not(windows))]
    {
        Command::new("npm")
    }
}
