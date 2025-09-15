mod cli;
mod dad;
mod ll;
mod rs;

use std::net::Ipv6Addr;

fn main() {
    let matches = cli::build().get_matches();
    let lladdr = matches
        .get_one::<String>(cli::IFACE)
        .map_or(
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            |iface| ll::get(iface).unwrap_or(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        );

    let iface_id: [u16; 4] = [0, 0, 0, 0x1234]; // TODO: randomize iface ID
    let target_addr = Ipv6Addr::new(
        0xfe80, 0, 0, 0,
        iface_id[0], iface_id[1], iface_id[2], iface_id[3],
    );
    eprintln!("Link local address: {:?}", target_addr);

    eprintln!("DAD start...");
    if let Err(e) = dad::resolve_iface_id(&target_addr) {
        eprintln!("{}", e);
        return
    }
    eprintln!("No duplicates");

    eprintln!("Advertise link local address: {:?}", target_addr);
    if let Err(e) = dad::advertise_addr(&target_addr) {
        eprintln!("{}", e);
        return
    }

    eprintln!("Resolve prefix...");
    let (prefix, prefix_length) = match rs::resolve_router_prefix(lladdr) {
        Ok((prefix, prefix_length)) => (prefix, prefix_length),
        Err(e) => {
            eprintln!("{}", e);
            return
        },
    };
    eprintln!("Prefix: {:?}/{}", prefix, prefix_length);

    eprintln!("DAD start...");
    let target_addr = Ipv6Addr::new(
        prefix.segments()[0], prefix.segments()[1], prefix.segments()[2], prefix.segments()[3], // TODO: using prefix_length
        iface_id[0], iface_id[1], iface_id[2], iface_id[3],
    );
    if let Err(e) = dad::resolve_iface_id(&target_addr) {
        eprintln!("{}", e);
        return
    }
    eprintln!("No duplicates");

    eprintln!("Advertise global address: {:?}", target_addr);
    if let Err(e) = dad::advertise_addr(&target_addr) {
        eprintln!("{}", e);
    }
    eprintln!("Global address: {:?}", target_addr);
}
