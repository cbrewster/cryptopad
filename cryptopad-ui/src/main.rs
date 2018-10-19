extern crate cryptopad;
extern crate gtk;

use gtk::prelude::*;
use gtk::{ButtonsType, DialogFlags, MessageDialog, MessageType, Window};

fn main() {
    let path = "test.enctxt";
    let text = "Woop woop!";
    let password = "pass123";
    cryptopad::save_text_to_file(path, text, password).unwrap();
    let decrypted = cryptopad::load_file(path, password).unwrap();
    println!("Decrypted text: {}", decrypted);

    if gtk::init().is_err() {
        println!("Failed to start GTK!");
        return;
    }

    MessageDialog::new(
        None::<&Window>,
        DialogFlags::empty(),
        MessageType::Info,
        ButtonsType::Ok,
        "Hello World",
    )
    .run();
}
