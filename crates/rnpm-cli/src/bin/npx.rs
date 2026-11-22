fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = rnpm_cli::npx::run_npx(&args);
    std::process::exit(code);
}
