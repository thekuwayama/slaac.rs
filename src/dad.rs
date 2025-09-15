extern crate anyhow;
extern crate pnet;

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmpv6::{Icmpv6Types, Icmpv6Code};
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, MutableNeighborAdvertPacket};
use pnet::transport::{self, TransportChannelType, TransportProtocol};

pub(crate) fn resolve_iface_id(target_addr: &Ipv6Addr) -> Result<(), String> {
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut ts, mut tr) = transport::transport_channel(4096, channel_type).map_err(|e| e.to_string())?;
    let mut tr = transport::icmpv6_packet_iter(&mut tr);

    let ns = gen_neighbor_solicit(target_addr)?;
    let dst = Ipv6Addr::new(
        0xff02, 0x0001, 0xff00, 0,
        target_addr.segments()[0], target_addr.segments()[1], target_addr.segments()[2], target_addr.segments()[3]
    );
    ts.set_ttl(255).map_err(|e| e.to_string())?;
    ts.send_to(ns, dst.into()).map_err(|e| e.to_string())?;

    match tr.next_with_timeout(Duration::from_secs(2)) {
        Ok(res) if res.is_none() => Ok(()),
        Ok(_) => Err(format!("{} has already used.", dst)),
        Err(e) => Err(e.to_string()),
    }
}

fn gen_neighbor_solicit<'a>(ip_addr: &Ipv6Addr) -> Result<MutableNeighborSolicitPacket<'a>, String> {
    let packet = vec![0u8; 24];
    let mut ns = MutableNeighborSolicitPacket::owned(packet).unwrap();
    ns.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns.set_icmpv6_code(Icmpv6Code(0));
    ns.set_target_addr(*ip_addr);

    Ok(ns)
}

pub(crate) fn advertise_addr(target_addr: &Ipv6Addr) -> Result<(), String> {
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut ts, _) = transport::transport_channel(4096, channel_type).map_err(|e| e.to_string())?;

    let na = gen_neighbor_advert(target_addr)?;
    let dst = IpAddr::from_str("ff02::1").unwrap();
    ts.set_ttl(255).map_err(|e| e.to_string())?;
    ts.send_to(na, dst).map_err(|e| e.to_string())?;

    Ok(())
}

fn gen_neighbor_advert<'a>(ip_addr: &Ipv6Addr) -> Result<MutableNeighborAdvertPacket<'a>, String> {
    let packet = vec![0u8; 24];
    let mut ns = MutableNeighborAdvertPacket::owned(packet).unwrap();
    ns.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
    ns.set_icmpv6_code(Icmpv6Code(0));
    ns.set_target_addr(*ip_addr);

    Ok(ns)
}
