extern crate clap;

use clap::{crate_description, crate_name, crate_version, Command, arg};

pub(crate) const IFACE: &str = "IFACE";

pub(crate) fn build() -> Command {
    Command::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(arg!(<IFACE>).long("iface").short('i').help("interface name").required(false))
}
