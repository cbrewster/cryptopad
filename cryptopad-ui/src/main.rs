extern crate cryptopad;

fn main() {
    let path = "test.enctxt";
    let text = "Woop woop!";
    let password = "pass123";
    cryptopad::save_text_to_file(path, text, password).unwrap();
    let decrypted = cryptopad::load_file(path, password).unwrap();
    println!("Decrypted text: {}", decrypted);
}
