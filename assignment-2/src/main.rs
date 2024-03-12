use std::fs;

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, /*Key,*/ KeyInit,      // did not use Key, so commented out to prevent Warning
};
use base64::prelude::*;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Called by `save_to_file_as_b64()`. Responsible for actually encoding the input data into Base64.
fn to_b64(data:&[u8]) -> String{
    let contents = BASE64_STANDARD.encode(data);
    contents
}

/// Called by `read_from_b64_file()`. Responsible for actually decoding the input data from Base64.
fn from_b64(contents: String) -> Vec<u8>{
    // 2. Decode the contents of the file using the engine BASE64_STANDARD
    BASE64_STANDARD.decode(contents).unwrap()
}

/// Save bytes to file encoded as Base64.
///
/// The data is encoded using the standard Base64 encoding engine and written to
/// disk.
///
/// # Arguments
///
/// * `file_name` - the path of the file in which the data is to be saved
/// * `data` - the data of to be saved to file
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn save_to_file_as_b64(file_name: &str, data: &[u8]) {
    // TODO 
    // unimplemented!()

    // 1. Encode data a a Base64 using the engine BASE64_STANDARD
    let contents = to_b64(&data);

    // 2. Write the contents of the Base64 string to the file given by file_name
    fs::write(file_name, contents)
            .expect("Unable to write file");
}

/// Read a Base64-encoded file as bytes.
///
/// The data is read from disk and decoded using the standard Base64 encoding
/// engine.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn read_from_b64_file(file_name: &str) -> Vec<u8> {
    // TODO
    // unimplemented!()

    // 1. Read the contents of the file given by file_name
    let contents = fs::read_to_string(file_name)
                            .expect("Unable to read file");
    from_b64(contents)
}

/// Returns a tuple containing a randomly generated secret key and public key.
///
/// The secret key is a StaticSecret that can be used in a Diffie-Hellman key
/// exchange. The public key is the associated PublicKey for the StaticSecret.
/// The output of this function is a tuple of bytes corresponding to these keys.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn keygen() -> ([u8; 32], [u8; 32]){
    // TODO
    // unimplemented!()

    // 1. Generate a StaticSecret from random
    let sk = StaticSecret::random();

    // 2. Generate a PublicKey from StaticSecret
    let pk = PublicKey::from(&sk);

    // 3. Convert the secret and public keys to bytes
    let sk_bytes = StaticSecret::to_bytes(&sk);
    let pk_bytes = PublicKey::to_bytes(&pk);

    // 4. Return a tuple of secret key bytes and public key bytes
    (sk_bytes,pk_bytes)
}

/// Called by `encrypt()` and `decrypt()`. Using the sender secret key and the receiver public key,
/// calculates the SharedSecret and returns as bytes.
fn perform_diffie_hellman(my_sk_b64: [u8; 32], their_pk_b64: [u8; 32]) -> [u8; 32] {

    // 1. Convert the sender secret key array into a StaticSecret
    let my_sk = StaticSecret::from(my_sk_b64);

    // 2. Convert the receiver public key into a PublicKey
    let their_pk = PublicKey::from(their_pk_b64);
        
    // 3. Perform Diffie-Hellman key exchange to generate a SharedSecret
    let shared_secret = my_sk.diffie_hellman(&their_pk);
    shared_secret.to_bytes()
}

/// Called by `encrypt()` and `decrypt()`. Hashes the SharedSecret byte array into a digest, then transforms the digest into
/// an AES key. Returns the digest in hex string, and the AES key.
fn hash_then_to_aes(shared_secret: [u8; 32]) -> (Aes256Gcm, String) {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let key = hasher.finalize();

    // Convert the digest into a hex string.
    let key_in_hex = format!("{:x}", key);

    // 5. Transform the hashed bytes into an AES-256-GCM key (Key<Aes256Gcm>)
    let cipher = Aes256Gcm::new(&key);
    // let cipher = Key::<Aes256Gcm>::from_slice(&key);     // error @key.encrypt() and decrypt()
    // let cipher: Key<Aes256Gcm> = key.into();             // error @ key.encrypt( and decrypt()
    (cipher, key_in_hex)
}

/// Called by `encrypt()`. Encrypts the message using the provided AES key and nonce into a ciphertet.
/// Appends the nonce to the end of the ciphertext to return the final encryption.
fn encrypt_then_parse(input: Vec<u8>, cipher: Aes256Gcm, nonce: &[u8]) -> (Vec<u8>, &[u8]){
    // 7. Encrypt the input under the AES-256-GCM key and nonce.
    let mut ciphertext = cipher.encrypt(nonce.into(), input.as_ref()).unwrap();

    // 8. Append the nonce to the end of the output vector containing the ciphertext
    ciphertext.append(&mut nonce.to_vec());
    (ciphertext, nonce)
}

/// Called by `decrpyt()`. Splits the input into a ciphertext and a nonce, then decrpyts the ciphertext with the nonce.
/// Returns the ecrypted message and the nonce.``
fn parse_then_decrypt(input: &Vec<u8>, cipher: Aes256Gcm) -> (Vec<u8>, &[u8]){
    // 6. Extract the ciphertext and the nonce from input. The last 12 bytes of input contains the nonce decrypt (generated in Step 7 of encrypt()).
    let (ciphertext,nonce) = input.split_at(input.len()-12);

    // 7. Decrypt the ciphertext using the AES-256-GCM key and nonce.
    let output = cipher.decrypt(nonce.into(), ciphertext).unwrap();
    
    (output, nonce)
}

/// Returns the encryption of plaintext data to be sent from a sender to a receiver.
///
/// This function performs a Diffie-Hellman key exchange between the sender's
/// secret key and the receiver's public key. Then, the function uses SHA-256 to
/// derive a symmetric encryption key, which is then used in an AES-256-GCM
/// encryption operation. The output vector contains the ciphertext with the
/// AES-256-GCM nonce (12 bytes long) appended to its end.
///
/// # Arguments
///
/// * `input` - A vector of bytes (`u8`) that represents the plaintext data to be encrypted.
/// * `sender_sk` - An array of bytes representing the secret key of the sender.
/// * `receiver_pk` - An array of bytes representing the public key of the receiver.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn encrypt(input: Vec<u8>, sender_sk: [u8; 32], receiver_pk: [u8; 32]) -> Vec<u8> {
    // TODO
    // unimplemented!()

    // Transform keys then perform DH key exchange to get SharedSecret
    let shared_secret = perform_diffie_hellman(sender_sk, receiver_pk);

    // Hash SharedSecret then transform into an AES key
    let (cipher,_) = hash_then_to_aes(shared_secret);

    // 6. Generate a random nonce for AES-256-GCM
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
     
    // Encrypt the input into a ciphertext, then append the nonce to the end
    let (ciphertext,_) = encrypt_then_parse(input, cipher, nonce.as_slice());
    ciphertext
}

/// Returns the decryption of ciphertext data to be received by a receiver from a sender.
///
/// This function performs a Diffie-Hellman key exchange between the receiver's
/// secret key and the sender's public key. Then, the function uses SHA-256 to
/// derive a symmetric encryption key, which is then used in an AES-256-GCM
/// decryption operation. The nonce for this decryption is the last 12 bytes of
/// the input. The output vector contains the plaintext.
///
/// # Arguments
///
/// * `input` - A vector of bytes that represents the ciphertext data to be encrypted and the associated nonce.
/// * `receiver_sk` - An array of bytes representing the secret key of the receiver.
/// * `sender_pk` - An array of bytes representing the public key of the sender.
///
/// # Note
///
/// You may **not** change the signature of this function.
///
fn decrypt(input: Vec<u8>, receiver_sk: [u8; 32], sender_pk: [u8; 32]) -> Vec<u8> {
    // TODO
    // unimplemented!()

    // Transform keys then perform DH key exchange to get SharedSecret
    let shared_secret = perform_diffie_hellman(receiver_sk, sender_pk);

    // Hash SharedSecret then transform into an AES key
    let (cipher,_) = hash_then_to_aes(shared_secret); 

    let (output, _) = parse_then_decrypt(&input, cipher);

    // 8. Return as vector of bytes 
    output
}

/// The main function, which parses arguments and calls the correct cryptographic operations.
///
/// # Note
///
/// **Do not modify this function**.
///
fn main() {
    keygen();

    // Collect command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Command parsing: keygen, encrypt, decrypt
    let cmd = &args[1];
    if cmd == "keygen" {
        // Arguments to the command
        let secret_key = &args[2];
        let public_key = &args[3];

        // Generate a secret and public key for this user
        let (sk_bytes, pk_bytes) = keygen();

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&secret_key, &sk_bytes);
        save_to_file_as_b64(&public_key, &pk_bytes);
    } else if cmd == "encrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let sender_sk = &args[4];
        let receiver_pk = &args[5];

        // Read input from file
        // Note that this input is not necessarily Base64-encoded
        let input = fs::read(input).unwrap();

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let sender_sk: [u8; 32] = read_from_b64_file(sender_sk).try_into().unwrap();
        let receiver_pk: [u8; 32] = read_from_b64_file(receiver_pk).try_into().unwrap();

        // Call the encryption operation
        let output_bytes = encrypt(input, sender_sk, receiver_pk);

        // Save those bytes as Base64 to file
        save_to_file_as_b64(&output, &output_bytes);
    } else if cmd == "decrypt" {
        // Arguments to the command
        let input = &args[2];
        let output = &args[3];
        let receiver_sk = &args[4];
        let sender_pk = &args[5];

        // Read the Base64-encoded input ciphertext from file
        let input = read_from_b64_file(&input);

        // Read the base64-encoded secret and public keys from file
        // Need to convert the Vec<u8> from this function into the 32-byte array for each key
        let receiver_sk: [u8; 32] = read_from_b64_file(&receiver_sk).try_into().unwrap();
        let sender_pk: [u8; 32] = read_from_b64_file(&sender_pk).try_into().unwrap();

        // Call the decryption operation
        let output_bytes = decrypt(input, receiver_sk, sender_pk);

        // Save those bytes as Base64 to file
        fs::write(output, output_bytes).unwrap();
    } else {
        panic!("command not found!")
    }
}

#[cfg(test)]
mod tests {             // - CAN BE AS DEVELOPER, WHITE BOX
    // TODO: Write tests that validate your encryption and decryption functionality
    // Use the values in README.md to write these tests - USE EXAMPLES FOLDER
    // You may have to split up function to write tests
    // For example, how can you test that both parties reach the same AES key? 

    use super::*;       // import so we can use the functions above

    // Instantiate A's and B's keys in Base64 from /examples for example-specific tests. This makes the keys known at compile time.
    const A_SK_B64: &str = include_str!("../examples/a_sk.txt");
    const A_PK_B64: &str = include_str!("../examples/a_pk.txt");
    const B_SK_B64: &str = include_str!("../examples/b_sk.txt");
    const B_PK_B64: &str = include_str!("../examples/b_pk.txt");

    // Instantiate A's and B's keys in bytes listed in [Assignment 2](https://tjo.is/teaching/sse-sp24/a2.html) for example-specific tests.
    const A_SK_BYTES: [u8; 32] = [77, 105, 123, 62, 170, 198, 29, 150, 82, 70, 152, 150, 38, 114, 94, 160, 7, 
                                    84, 131, 221, 130, 89, 77, 243, 191, 147, 174, 121, 49, 91, 187, 214];
    const B_PK_BYTES: [u8; 32] = [246, 88, 196, 62, 121, 69, 20, 123, 199, 128, 26, 114, 238, 35, 255, 153, 209, 
                                    43, 110, 231, 78, 227, 115, 192, 90, 20, 40, 5, 151, 98, 253, 123];
    const A_PK_BYTES: [u8; 32] = [30, 142, 43, 24, 172, 129, 55, 138, 115, 90, 233, 202, 162, 74, 49, 37, 111,
                                    215, 214, 13, 51, 75, 19, 255, 87, 44, 170, 227, 217, 121, 217, 34];
    const B_SK_BYTES: [u8; 32] = [45, 203, 5, 168, 176, 17, 244, 93, 85, 7, 38, 91, 166, 223, 208, 58, 83, 180,
                                    175, 225, 226, 207, 80, 104, 97, 11, 46, 234, 214, 48, 39, 37];
    

    /*********** GENERIC TESTS ***********/

    /// TEST: Encryption and decryption from an internal String value.
    #[test]                 //  to signal that the following is a test function, must do for each test
    fn encrypts_and_decrypts() {
        // Generate sender and receiver keys
        let (sender_sk, sender_pk) = keygen();
        let (receiver_sk, receiver_pk) = keygen();

        // Define a plaintext message to encrypt
        let plaintext = b"Hello, world!";
        
        // Encrypt the message using the sender's secret key and receiver's public key
        let ciphertext = encrypt(plaintext.to_vec(), sender_sk, receiver_pk);
        
        // Decrypt the ciphertext using the receiver's secret key and sender's public key
        let decrypted_text = decrypt(ciphertext, receiver_sk, sender_pk);

        // Ensure that the decrypted text matches the original plaintext
        assert_eq!(decrypted_text, plaintext);
    }

    /// TEST: Encryption and decryption must work regardless of the size of payload.
    #[test]           
    fn encrypts_and_decrypts_diff_sizes() {
        // Generate secret and public keys for 2 parties
        let (sender_sk, sender_pk) = keygen();
        let (receiver_sk, receiver_pk) = keygen();

        // Test with small input
        let plaintext_small = b"Small message";
        let ciphertext_small = encrypt(plaintext_small.to_vec(), sender_sk, receiver_pk);
        let decrypted_text_small = decrypt(ciphertext_small, receiver_sk, sender_pk);
        assert_eq!(decrypted_text_small, plaintext_small);

        // Test with large input
        let plaintext_large = vec![0; 1024]; 
        let ciphertext_large = encrypt(plaintext_large.clone(), sender_sk, receiver_pk);
        let decrypted_text_large = decrypt(ciphertext_large, receiver_sk, sender_pk);
        assert_eq!(decrypted_text_large, plaintext_large);
    }

    /// TEST: Successful encryption and decryption of the message must not be by chance, so try multiple times.
    #[test]      
    fn encrypts_and_decrypts_multiple_times() {
        // Generate secret and public keys for 2 parties
        let (sender_sk, sender_pk) = keygen();
        let (receiver_sk, receiver_pk) = keygen();
    
        let plaintext = b"Secret message";
    
        // Encrypt and decrypt multiple times
        for _ in 0..5 {
            let ciphertext = encrypt(plaintext.to_vec(), sender_sk, receiver_pk);
            let decrypted_text = decrypt(ciphertext, receiver_sk, sender_pk);
            assert_eq!(decrypted_text, plaintext);
        }
    }
    
    /*********** EXAMPLE-SPECIFIC TESTS ***********/

    /// A test-dedicated function. Calculates the SharedSecret from the given byte-array keys. The SharedSecret is calculated
    /// using an established function from `x25519_dalek`. Returns the SharedSecret byte-arrays from A and B.
    fn true_shared_secret() -> ([u8; 32],[u8; 32]){
         use x25519_dalek::x25519;
    
        let a_shared_truth: [u8; 32] = x25519(A_SK_BYTES, B_PK_BYTES);
        let b_shared_truth: [u8; 32] = x25519(B_SK_BYTES, A_PK_BYTES);
        
        // Ensure that the ground truth is suitable.
        if a_shared_truth != b_shared_truth{
            panic!("!!!!!!!!! UNSUITABLE GROUND TRUTH !!!!!!!!!");
        }
        assert_eq!(&a_shared_truth, &b_shared_truth);
        (a_shared_truth, b_shared_truth)
    }

    /// TEST: Decode given Base64 keys using `from_b64()`, then compare results with given byte-array keys. Check for all the given keys.
    #[test]         
    fn decodes_from_b64(){
        let a_sk: [u8;32] = from_b64(A_SK_B64.to_string()).try_into().unwrap();
        assert_eq!(A_SK_BYTES, a_sk);

        let a_pk: [u8;32] = from_b64(A_PK_B64.to_string()).try_into().unwrap();
        assert_eq!(A_PK_BYTES, a_pk);

        let b_sk: [u8;32] = from_b64(B_SK_B64.to_string()).try_into().unwrap();
        assert_eq!(B_SK_BYTES, b_sk);

        let b_pk: [u8;32] = from_b64(B_PK_B64.to_string()).try_into().unwrap();
        assert_eq!(B_PK_BYTES, b_pk);
    }

    /// TEST: Encode given byte-array keys using `to_b64()`, then compare results with given Base64 keys. Check for all the given keys.
    #[test]  
    fn encodes_to_b64(){
        let a_sk: String = to_b64(&A_SK_BYTES);
        assert_eq!(A_SK_B64, a_sk);

        let a_pk: String = to_b64(&A_PK_BYTES);
        assert_eq!(A_PK_B64, a_pk);

        let b_sk: String = to_b64(&B_SK_BYTES);
        assert_eq!(B_SK_B64, b_sk);

        let b_pk: String = to_b64(&B_PK_BYTES);
        assert_eq!(B_PK_B64, b_pk);
    }

    /// TEST: Calculates the SharedSecret from A's side and from B's side using `perform_diffie_hellman()`. The results must match the byte
    /// arrays from `true_shared_secret()` for both A and B. Thus, the results of `perform_diffie_hellman()` must also equal each other.
    #[test]          
    fn reaches_same_shared_secret(){        
        /* Setting up ground truth */
        let (a_shared_truth, b_shared_truth) = true_shared_secret();
        
        /* Testing */
        let a_shared_secret = perform_diffie_hellman(A_SK_BYTES, B_PK_BYTES);
        let b_shared_secret = perform_diffie_hellman(B_SK_BYTES, A_PK_BYTES);
    
        assert_eq!(a_shared_truth, a_shared_secret);
        assert_eq!(b_shared_truth, b_shared_secret);
        assert_eq!(a_shared_secret, b_shared_secret);
    }

    /// TEST: When hashed using `hash_then_to_aes()`, the SharedSecret byte arrays from A and from B must result to the same digest.
    /// The digests are compared as hex-strings. 
    #[test]
    fn hashes_to_same_digest(){
        let (a_shared_secret, b_shared_secret) = true_shared_secret();
        let (_,a_cipher_hex) = hash_then_to_aes(a_shared_secret);
        let (_,b_cipher_hex) = hash_then_to_aes(b_shared_secret);

        assert_eq!(a_cipher_hex,b_cipher_hex);
    }

    /// TEST: The resulting digest from `hash_then_to_aes()` must not be the same even if there is a slight change in the input byte array.
    #[test]
    fn diff_bytes_diff_digest(){
        /* Setting up ground truth */
        let (shared_secret1, _) = true_shared_secret();
        let (_, cipher1_hex) = hash_then_to_aes(shared_secret1);

        /* Testing */
        // Copy the original array, then make a small change by adding 1 to the first element
        let mut shared_secret2 = shared_secret1.clone();
        shared_secret2[0] = shared_secret2[0]+1;
        let (_, cipher2_hex) = hash_then_to_aes(shared_secret2);

        assert_ne!(cipher1_hex, cipher2_hex);
    }

    /// TEST: The encryption of the same message must be the same if the same nonce is used to encrypt it by the same sender.
    /// The nonce is taken from the decryption/receiver side, which is then used to encrypt the same message on the sender side.
    /// The resulting encryption is compared with the given encrypted message in /examples.
    #[test]
    fn same_encrypt_with_nonce_from_decrypt(){
        /* Decryption on B's side */
        // Read the Base64-encoded input ciphertext from file
        let encrypted_msg = read_from_b64_file("examples/example1_enc.txt");

        // Transform keys then perform DH key exchange to get SharedSecret
        let b_shared_secret = perform_diffie_hellman(B_SK_BYTES, A_PK_BYTES);

        // Hash SharedSecret then transform into an AES key
        let (b_cipher,_) = hash_then_to_aes(b_shared_secret); 
        let (_, nonce) = parse_then_decrypt(&encrypted_msg, b_cipher);

        /* Encryption on A's side */
        let msg_to_encrypt = fs::read("examples/example1.jpg").unwrap();

        // Transform keys then perform DH key exchange to get SharedSecret
        let a_shared_secret = perform_diffie_hellman(A_SK_BYTES, B_PK_BYTES);

        // Hash SharedSecret then transform into an AES key
        let (a_cipher,_) = hash_then_to_aes(a_shared_secret);
        let (ciphertext, _) = encrypt_then_parse(msg_to_encrypt, a_cipher, nonce);

        assert_eq!(encrypted_msg,ciphertext);
    }

    /// TEST: The input message to be encrypted must be the same as the output message from the decryption.
    #[test]
    fn dec_msg_same_as_enc_msg(){
        let msg_to_encrypt: Vec<u8> = fs::read("examples/example1.jpg").unwrap();
        let encrypted_msg = encrypt(msg_to_encrypt.clone(), A_SK_BYTES, B_PK_BYTES);
        let decrypted_msg = decrypt(encrypted_msg, B_SK_BYTES, A_PK_BYTES);
        assert_eq!(msg_to_encrypt, decrypted_msg);
    }
}


