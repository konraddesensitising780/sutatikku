use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;
use tempfile::tempdir;

fn run_with_timeout<F: FnOnce() + Send + 'static>(dur: Duration, f: F) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    rx.recv_timeout(dur).expect("Test timed out");
}

#[test]
fn test_basic_bundling_ls_tempdir() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("myls");

        let input_bin = if fs::metadata("/bin/ls").is_ok() {
            "/bin/ls"
        } else {
            "/usr/bin/ls"
        };
        println!("Bundling {} with --use-tempdir", input_bin);

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg(input_bin)
            .arg("-o")
            .arg(&output_bin)
            .arg("--use-tempdir")
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());
        assert!(output_bin.exists());

        let status = Command::new(&output_bin)
            .arg("/")
            .status()
            .expect("Failed to run bundled binary");

        assert!(status.success());
    });
}

#[test]
fn test_in_memory_bundling_cat_default() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("mycat_mem");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };
        println!("Bundling {} (default memfd)", input_bin);

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg(input_bin)
            .arg("-o")
            .arg(&output_bin)
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());
        assert!(output_bin.exists());

        let test_file = temp.path().join("hello.txt");
        fs::File::create(&test_file)
            .unwrap()
            .write_all(b"Hello from memory bundle!")
            .unwrap();

        let output = Command::new(&output_bin)
            .arg(&test_file)
            .output()
            .expect("Failed to run bundled cat");

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "Hello from memory bundle!"
        );
    });
}

#[test]
fn test_resource_bundling_cat() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("mycat_with_res");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };

        let resource_file = temp.path().join("fake_foo");
        fs::write(&resource_file, "fake foo!").unwrap();

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg(input_bin)
            .arg("-o")
            .arg(&output_bin)
            .arg("--files")
            .arg(format!("{}:/tmp/foo", resource_file.to_str().unwrap()))
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());

        let output = Command::new(&output_bin)
            .arg("/tmp/foo")
            .output()
            .expect("Failed to run bundled binary");

        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "fake foo!");
    });
}

#[test]
fn test_yaml_config_bundling() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("mycat_config");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };

        let resource_file = temp.path().join("fake_bar");
        fs::write(&resource_file, "fake bar!").unwrap();

        let config_path = temp.path().join("config.yaml");
        let config_content = format!(
            "entry:\n  path: {}\nfiles:\n  - path: {}\n    map_to: /tmp/bar\n",
            input_bin,
            resource_file.to_str().unwrap()
        );
        fs::write(&config_path, config_content).unwrap();

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg("--config")
            .arg(&config_path)
            .arg("-o")
            .arg(&output_bin)
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());

        let output = Command::new(&output_bin)
            .arg("/tmp/bar")
            .output()
            .expect("Failed to run bundled binary");

        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "fake bar!");
    });
}

#[test]
fn test_prefer_host_redirection() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("mycat_prefer_host");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };

        let host_file = temp.path().join("runtime_file.txt");
        fs::write(&host_file, "host version").unwrap();

        let bundled_source = temp.path().join("bundled_source.txt");
        fs::write(&bundled_source, "bundled version").unwrap();

        let config_path = temp.path().join("config.yaml");
        let config_content = format!(
            "entry:\n  path: {}\nfiles:\n  - path: {}\n    map_to: {}\n    prefer_host: true\n",
            input_bin,
            bundled_source.to_str().unwrap(),
            host_file.to_str().unwrap()
        );
        fs::write(&config_path, config_content).unwrap();

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg("--config")
            .arg(&config_path)
            .arg("-o")
            .arg(&output_bin)
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());

        let output = Command::new(&output_bin)
            .arg(&host_file)
            .output()
            .expect("Failed to run bundled binary");

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "host version"
        );
    });
}

#[test]
fn test_entry_default_args() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("mycat_with_args");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };

        let test_file = temp.path().join("args_test.txt");
        fs::write(&test_file, "args working").unwrap();

        let config_path = temp.path().join("config.yaml");
        let config_content = format!(
            "entry:\n  path: {}\n  args: [\"{}\"]\n",
            input_bin,
            test_file.to_str().unwrap()
        );
        fs::write(&config_path, config_content).unwrap();

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg("--config")
            .arg(&config_path)
            .arg("-o")
            .arg(&output_bin)
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());

        let output = Command::new(&output_bin)
            .output()
            .expect("Failed to run bundled binary");

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "args working"
        );
    });
}

#[test]
fn test_explicit_library_inclusion() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let output_bin = temp.path().join("mycat_with_libs");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };
        let libselinux = "/lib/x86_64-linux-gnu/libselinux.so.1";

        if !Path::new(libselinux).exists() {
            return;
        }

        let status = Command::new(sutatikku_bin)
            .arg("build")
            .arg(input_bin)
            .arg("-o")
            .arg(&output_bin)
            .arg("--files")
            .arg(libselinux)
            .status()
            .expect("Failed to run sutatikku build");

        assert!(status.success());

        let output = Command::new(&output_bin)
            .arg("--version")
            .output()
            .expect("Failed to run bundled binary");

        assert!(output.status.success());
    });
}

#[test]
fn test_config_generation_simple() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let config_out = temp.path().join("gen_config.yaml");

        let input_bin = if fs::metadata("/bin/ls").is_ok() {
            "/bin/ls"
        } else {
            "/usr/bin/ls"
        };

        let status = Command::new(sutatikku_bin)
            .arg("gen-config")
            .arg(input_bin)
            .arg("--output")
            .arg(&config_out)
            .status()
            .expect("Failed to run sutatikku gen-config");

        assert!(status.success());
        assert!(config_out.exists());

        let content = fs::read_to_string(&config_out).unwrap();
        assert!(content.contains("entry:"));
        assert!(content.contains("path:"));
        assert!(content.contains("files:"));
        assert!(content.contains("libc.so"));
    });
}

#[test]
fn test_config_generation_recording() {
    run_with_timeout(Duration::from_secs(30), || {
        let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
        let temp = tempdir().unwrap();
        let config_out = temp.path().join("recorded_config.yaml");

        let input_bin = if fs::metadata("/bin/cat").is_ok() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };
        let test_file = temp.path().join("to_be_recorded.txt");
        fs::write(&test_file, "record me!").unwrap();

        let non_existent = temp.path().join("does_not_exist.txt");

        let status = Command::new(sutatikku_bin)
            .arg("gen-config")
            .arg(input_bin)
            .arg("--output")
            .arg(&config_out)
            .arg("--record")
            .arg("--")
            .arg(&test_file)
            .arg(&non_existent)
            .status()
            .expect("Failed to run sutatikku gen-config --record");

        assert!(status.success());
        assert!(config_out.exists());

        let content = fs::read_to_string(&config_out).unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();
        let files = yaml["files"].as_sequence().unwrap();

        let file_paths: Vec<String> = files
            .iter()
            .map(|f| {
                f.as_str()
                    .unwrap_or_else(|| f["path"].as_str().unwrap())
                    .to_string()
            })
            .collect();

        assert!(file_paths.contains(&test_file.to_str().unwrap().to_string()));
        assert!(!file_paths.contains(&non_existent.to_str().unwrap().to_string()));

        let mut sorted_paths = file_paths.clone();
        sorted_paths.sort();
        assert_eq!(
            file_paths, sorted_paths,
            "Files should be sorted alphabetically"
        );
    });
}
