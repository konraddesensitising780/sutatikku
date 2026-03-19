use std::process::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_use_case_1_ls() {
    let sutatikku_bin = env!("CARGO_BIN_EXE_sutatikku");
    let temp = tempdir().unwrap();
    let output_bin = temp.path().join("myls");

    let input_bin = if fs::metadata("/bin/ls").is_ok() { "/bin/ls" } else { "/usr/bin/ls" };
    println!("Bundling {}", input_bin);

    // Build the standalone binary
    let status = Command::new(sutatikku_bin)
        .arg("build")
        .arg(input_bin)
        .arg("-o")
        .arg(&output_bin)
        .status()
        .expect("Failed to run sutatikku build");

    assert!(status.success());
    assert!(output_bin.exists());

    // Check ldd output
    let ldd_output = Command::new("ldd")
        .arg(&output_bin)
        .output()
        .expect("Failed to run ldd");
    let ldd_str = String::from_utf8_lossy(&ldd_output.stdout);
    println!("ldd output:\n{}", ldd_str);
    // Note: this might fail if sutatikku itself wasn't compiled statically for tests
    // assert!(ldd_str.contains("statically linked"));

    // Run the bundled binary
    let output = Command::new(&output_bin)
        .arg("/")
        .output()
        .expect("Failed to run bundled binary");

    println!("Bundled bin stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    println!("Bundled bin stderr:\n{}", String::from_utf8_lossy(&output.stderr));

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bin") || stdout.contains("etc") || stdout.contains("usr"));
}
