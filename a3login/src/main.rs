///
/// [ASSIGNMENT 3](https://tjo.is/teaching/sse-sp24/a3.html)
///

use csv;
use argon2::{
    password_hash::{
        PasswordHash, PasswordVerifier,
    },
    Argon2
};

use std::{error::Error, fs, io, path, process};

fn db_exists(file_name: &str) {
    if path::Path::new(file_name).is_file(){
        return;
    } else{
        println!("{} does not exist!", file_name);
        process::exit(0);
    }
}

fn get_user_input(prompt: &str) -> String{
    println!("{}", prompt);
    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .expect("Failed to read your input.");

    input.trim().to_string()

    /*
    How to handle empty entries: print warning then loop until user actually puts something 
     */
}


fn lookup_in_db(input: &str, file_name: &str) -> String {
    let file = fs::File::open(file_name)
                .expect("Error! Access denied! --> Failed to open password database.");
    let mut rdr = csv::ReaderBuilder::new()
                .has_headers(false)            // the CSV file has no column names
                .from_reader(file);

    for record in rdr.records(){         // iterate through rows in the CSV file
        let record = record 
                .expect("Error! Access denied! --> Cannot read record in password database."); 
        if let Some(username) = record.get(0){                  // get row's first column entry; should be the username
            if username.trim() == input{                              // if the entry matches the user input
                if let Some(stored_pwd) = record.get(1){         // get row's second column entry; should be the hashed password
                    return stored_pwd.to_string();           // return the hashed password as string
                }
            } 
        }
    }
    println!("Error! Access denied! --> No username match!");
    process::exit(0);
}

fn verify_password(stored_pwd: &str, input_pwd: &str) -> Result<(), Box<dyn Error>>{
    let parsed_hash = PasswordHash::new(&stored_pwd)
        .expect("Error! Access denied! --> Failed to parse stored password.");

    if Argon2::default().verify_password(input_pwd.as_bytes(), &parsed_hash).is_ok(){
        // If the password has does verify, display a success message and exit
        println!("Access granted!");
        process::exit(0);
    } else {
        // If the password hash did not verify, display an error message and exit
        println!("Error! Access denied!");
        process::exit(0);
    }
}

fn main(){

    // 1. Read filename from disk as a CSV file.
    let args: Vec<String> = std::env::args().collect();
    let cmd = &args[1];
    db_exists(&cmd);

    // 2. Ask for a username and store the input.
    let username: String = get_user_input("Enter username: ");

    // 3. Ask for a password and store the input.
    let password: String = get_user_input("Enter password: ");

    // 4. Look through the CSV file to find the username from the input.
    // 5. Load the passwords hash string from the CSV file for the username
    let stored_pwd: String = lookup_in_db(&username, &cmd);

    // 6. Verify the password has from the CSV file with the password that was input
    let _ = verify_password(&stored_pwd, &password);
}
