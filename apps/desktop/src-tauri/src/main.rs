#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("elevated-worker") {
        let mut req_path: Option<std::path::PathBuf> = None;
        let mut resp_path: Option<std::path::PathBuf> = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--request" if i + 1 < args.len() => {
                    req_path = Some(std::path::PathBuf::from(&args[i + 1]));
                    i += 2;
                }
                "--response" if i + 1 < args.len() => {
                    resp_path = Some(std::path::PathBuf::from(&args[i + 1]));
                    i += 2;
                }
                _ => i += 1,
            }
        }
        match (req_path, resp_path) {
            (Some(req), Some(resp)) => match clearlens_core::run_elevation_worker_files(&req, &resp) {
                Ok(res) if res.success => std::process::exit(0),
                Ok(res) => {
                    eprintln!("elevated worker error: {}", res.message);
                    std::process::exit(1);
                }
                Err(err) => {
                    eprintln!("elevated worker error: {err}");
                    std::process::exit(1);
                }
            },
            _ => {
                eprintln!("usage: elevated-worker --request <path> --response <path>");
                std::process::exit(1);
            }
        }
    }

    clearlens_desktop_lib::run()
}
