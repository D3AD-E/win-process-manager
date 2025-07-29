use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

pub fn monitor_appdata_for_prefix(prefix: &str) {
    use std::env;

    let appdata = env::var("LOCALAPPDATA").expect("Could not get LOCALAPPDATA");
    let appdata_path = PathBuf::from(appdata).join("Temp");

    let found_dir = env::current_dir().unwrap().join("found");
    if !found_dir.exists() {
        fs::create_dir_all(&found_dir).expect("Could not create /found/ directory");
    }

    println!(
        "Monitoring {:?} for new files starting with '{}'...",
        appdata_path, prefix
    );
    let mut seen: HashSet<PathBuf> = HashSet::new();

    loop {
        if let Ok(entries) = fs::read_dir(&appdata_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with(prefix) && !seen.contains(&path) {
                            let dest = found_dir.join(name);
                            if fs::copy(&path, &dest).is_ok() {
                                println!("Copied new file: {:?}", name);
                                seen.insert(path.clone());
                            }
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}
