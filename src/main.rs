mod rs;
mod cli;
mod dad;
mod ll;

use std::net::Ipv6Addr;

fn main() {
    let matches = cli::build().get_matches();
    let lladdr = matches
        .get_one::<String>(cli::IFACE)
        .map_or(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00], |iface| ll::get(iface).unwrap_or(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

    let iface_id: [u16; 4] = [0, 0, 0, 0x1234];
    let target_addr = Ipv6Addr::new(
        0xfe80, 0, 0, 0,
        iface_id[0], iface_id[1], iface_id[2], iface_id[3],
    );
    if let Err(e) = dad::resolve_iface_id(&target_addr) {
        println!("{}", e);
        return
    }

    let prefix = match rs::resolve_router_prefix(lladdr) {
        Ok(prefix) => prefix,
        Err(msg) => {
            println!("{}", msg);
            return
        },
    };

    let target_addr = Ipv6Addr::new(
        prefix.segments()[4], prefix.segments()[5], prefix.segments()[6], prefix.segments()[7],
        iface_id[0], iface_id[1], iface_id[2], iface_id[3],
    );
    if let Err(e) = dad::resolve_iface_id(&target_addr) {
        println!("{}", e);
    }
}
