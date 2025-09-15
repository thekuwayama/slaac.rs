mod rs;
mod cli;
mod ll;

fn main() {
    let matches = cli::build().get_matches();
    let lladdr = matches
        .get_one::<String>(cli::IFACE)
        .map_or(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00], |iface| ll::get(iface).unwrap_or(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

    match rs::resolve_router_prefix(lladdr) {
        Ok(prefix) => println!("{:?}", prefix), 
        Err(msg) => println!("{}", msg),
    };
}
