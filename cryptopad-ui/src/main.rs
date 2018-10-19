extern crate cryptopad;
extern crate gio;
extern crate gtk;
extern crate gtk_sys;
#[macro_use]
extern crate relm;
extern crate relm_attributes;
#[macro_use]
extern crate relm_derive;

use cryptopad::{CryptoFile, EncryptedFile, SaveOption};
use gio::{File, FileExt};
use gtk::prelude::*;
use gtk::{TextBufferExt, Window, WindowType};
use gtk_sys::{GTK_RESPONSE_ACCEPT, GTK_RESPONSE_CANCEL, GTK_RESPONSE_OK, GTK_RESPONSE_YES};
use relm::{Relm, Update, Widget};
use std::path::PathBuf;

pub struct Model {
    relm: Relm<Win>,
    buffer: String,
    path: Option<PathBuf>,
    opening: Option<PathBuf>,
}

#[derive(Msg)]
pub enum Msg {
    Quit,
    BufferUpdated(String),
    OpenFile,
    SaveFile,
    ReadError(gtk::Error),
    FileRead((Vec<u8>, String)),
    SetBuffer(String),
    SetPath(Option<PathBuf>),
}

struct Win {
    model: Model,
    window: Window,
    widgets: Widgets,
}

struct Widgets {
    text_view: gtk::TextView,
}

impl Update for Win {
    type Model = Model;
    type ModelParam = ();
    type Msg = Msg;

    fn model(relm: &Relm<Self>, _: ()) -> Model {
        Model {
            relm: relm.clone(),
            buffer: String::from("Test"),
            path: None,
            opening: None,
        }
    }

    // The model may be updated when a message is received.
    // Widgets may also be updated in this function.
    fn update(&mut self, event: Msg) {
        match event {
            Msg::Quit => gtk::main_quit(),
            Msg::BufferUpdated(buffer) => self.model.buffer = buffer,
            Msg::OpenFile => self.open_file(),
            Msg::SaveFile => self.save_file(),
            Msg::FileRead((contents, _)) => {
                self.read_file(contents);
            }
            Msg::ReadError(_) => {
                println!("An error occurred opening the file!");
                self.model.opening = None;
            }
            Msg::SetPath(path) => {
                self.model.path = path;
                match &self.model.path {
                    Some(path) => self
                        .window
                        .set_title(&format!("Cryptopad • {}", path.display())),
                    None => self.window.set_title("Cryptopad"),
                }
            }
            Msg::SetBuffer(buffer) => {
                self.widgets
                    .text_view
                    .get_buffer()
                    .unwrap()
                    .set_text(&buffer);
                self.model.buffer = buffer;
            }
        }
    }
}

impl Widget for Win {
    type Root = Window;

    fn root(&self) -> Self::Root {
        self.window.clone()
    }

    fn view(relm: &Relm<Self>, model: Self::Model) -> Self {
        let window = Window::new(WindowType::Toplevel);
        let scroller = gtk::ScrolledWindow::new(None, None);
        scroller.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        window.add(&scroller);

        connect!(
            relm,
            window,
            connect_delete_event(_, _),
            return (Some(Msg::Quit), Inhibit(false))
        );

        window.set_title("Cryptopad");
        window.set_default_size(800, 600);

        let container = gtk::Box::new(gtk::Orientation::Vertical, 0);
        scroller.add(&container);
        let text_view = gtk::TextView::new();
        container.pack_start(&text_view, true, true, 0);
        text_view.get_buffer().unwrap().set_text(&model.buffer);
        text_view.set_bottom_margin(5);
        text_view.set_top_margin(5);
        text_view.set_right_margin(5);
        text_view.set_left_margin(5);

        let container = gtk::HeaderBar::new();
        container.set_show_close_button(true);
        container.set_title("Cryptopad");
        let open_button = gtk::Button::new_with_label("Open File");
        container.pack_start(&open_button);
        connect!(relm, open_button, connect_clicked(_), Msg::OpenFile);

        let save_button = gtk::Button::new_with_label("Save File");
        container.pack_start(&save_button);
        connect!(relm, save_button, connect_clicked(_), Msg::SaveFile);

        window.set_titlebar(&container);

        connect!(
            relm,
            text_view.get_buffer().unwrap(),
            connect_property_text_notify(buffer),
            {
                let (start, end) = buffer.get_bounds();
                Msg::BufferUpdated(buffer.get_text(&start, &end, true).unwrap())
            }
        );

        window.show_all();

        Win {
            model,
            window,
            widgets: Widgets { text_view },
        }
    }
}

impl Win {
    fn open_file(&mut self) {
        if let Some(filename) = self.get_file(gtk::FileChooserAction::Open) {
            self.model.opening = Some(filename.clone());
            let file = File::new_for_path(filename);
            connect_async!(
                file,
                load_contents_async,
                self.model.relm,
                Msg::FileRead,
                Msg::ReadError
            );
        }
    }

    fn read_file(&mut self, contents: Vec<u8>) {
        let file = CryptoFile::new(contents).unwrap();
        match file {
            CryptoFile::Plain(text) => {
                self.update(Msg::SetPath(self.model.opening.clone()));
                self.model.opening = None;
                self.update(Msg::SetBuffer(text));
            }
            CryptoFile::Encrypted(file) => {
                self.decrypt_file(file);
            }
        }
    }

    fn decrypt_file(&mut self, file: EncryptedFile) {
        match self.get_password() {
            Some(password) => {
                if let Ok(contents) = file.try_decrypt(&password) {
                    self.update(Msg::SetBuffer(contents));
                } else {
                    self.model.opening = None;
                    let dialog = gtk::MessageDialog::new(
                        Some(&self.window),
                        gtk::DialogFlags::empty(),
                        gtk::MessageType::Error,
                        gtk::ButtonsType::Ok,
                        "Invalid Password",
                    );
                    dialog.run();
                    dialog.destroy();
                }
            }
            None => {
                self.model.opening = None;
            }
        };
    }

    fn save_file(&mut self) {
        if let Some(filename) = self.get_file(gtk::FileChooserAction::Save) {
            let save_option = match self.ask_to_encrypt() {
                true => {
                    if let Some(password) = self.get_password() {
                        Some(SaveOption::Encrypted(password))
                    } else {
                        None
                    }
                }
                false => Some(SaveOption::Plain),
            };

            if let Some(save_option) = save_option {
                cryptopad::save_text_to_file(filename.clone(), &self.model.buffer, save_option)
                    .unwrap();
                self.update(Msg::SetPath(Some(filename)));
            }
        }
    }

    fn get_password(&mut self) -> Option<String> {
        let dialog = gtk::MessageDialog::new(
            Some(&self.window),
            gtk::DialogFlags::empty(),
            gtk::MessageType::Question,
            gtk::ButtonsType::OkCancel,
            "Enter the password:",
        );
        let entry = gtk::Entry::new();
        entry.set_visibility(false);
        entry.set_invisible_char('•');

        dialog.get_content_area().pack_end(&entry, false, false, 5);
        dialog.show_all();
        let result = dialog.run();
        let result = if result == GTK_RESPONSE_OK {
            entry.get_text()
        } else {
            None
        };
        dialog.destroy();
        result
    }

    fn get_file(&mut self, action: gtk::FileChooserAction) -> Option<PathBuf> {
        let dialog = gtk::FileChooserDialog::new(Some("Open a file"), Some(&self.window), action);
        if let Some(path) = &self.model.path {
            dialog.set_filename(path);
        }
        dialog.add_button("Cancel", GTK_RESPONSE_CANCEL);
        dialog.add_button("Accept", GTK_RESPONSE_ACCEPT);
        let result = dialog.run();
        let result = if result == GTK_RESPONSE_ACCEPT {
            dialog.get_filename()
        } else {
            None
        };
        dialog.destroy();
        result
    }

    fn ask_to_encrypt(&mut self) -> bool {
        let dialog = gtk::MessageDialog::new(
            Some(&self.window),
            gtk::DialogFlags::empty(),
            gtk::MessageType::Question,
            gtk::ButtonsType::YesNo,
            "Do You Wish To Encrypt?",
        );
        let result = dialog.run() == GTK_RESPONSE_YES;
        dialog.destroy();
        result
    }
}

fn main() {
    Win::run(()).unwrap();
}
