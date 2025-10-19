extern crate anyhow;
extern crate pnet;

use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmpv6::{self, Icmpv6Types, Icmpv6Packet};
use pnet::packet::icmpv6::ndp::{Icmpv6Codes, MutableNeighborSolicitPacket, MutableNeighborAdvertPacket, NdpOption, NdpOptionTypes};
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};

pub(crate) fn resolve_iface_id(target_addr: &Ipv6Addr, lladdr: &[u8]) -> Result<(), String> {
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut ts, mut tr) = transport::transport_channel(4096, channel_type).map_err(|e| e.to_string())?;
    let mut tr = transport::icmpv6_packet_iter(&mut tr);

    let dst = Ipv6Addr::new(
        0xff02, 0x0001, 0xff00, 0,
        target_addr.segments()[0], target_addr.segments()[1], target_addr.segments()[2], target_addr.segments()[3]
    );
    let ns = gen_neighbor_solicit(target_addr, lladdr, &dst)?;
    ts.set_ttl(255).map_err(|e| e.to_string())?;
    ts.send_to(ns, dst.into()).map_err(|e| e.to_string())?;

    match tr.next_with_timeout(Duration::from_secs(2)) {
        Ok(res) if res.is_none() => Ok(()),
        Ok(_) => Err(format!("{} has already used.", dst)), // TODO: parse NA
        Err(e) => Err(e.to_string()),
    }
}

fn gen_neighbor_solicit<'a>(ip_addr: &'a Ipv6Addr, lladdr: &'a [u8], dst: &'a Ipv6Addr) -> Result<MutableNeighborSolicitPacket<'a>, String> {
    let packet = vec![0u8; 32];
    let options = [NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: lladdr.to_owned(),
    }];
    let mut ns = MutableNeighborSolicitPacket::owned(packet).unwrap();
    ns.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns.set_icmpv6_code(Icmpv6Codes::NoCode);
    ns.set_target_addr(*ip_addr);
    ns.set_options(&options[..]);
    ns.set_checksum(0xffff);
    let icmpv6_packet = Icmpv6Packet::new(ns.packet()).ok_or("Failed to construct ICMPv6Packet")?;
    let checksum = icmpv6::checksum(&icmpv6_packet, &Ipv6Addr::UNSPECIFIED, dst);
    ns.set_checksum(checksum);

    Ok(ns)
}

pub(crate) fn advertise_addr(target_addr: &Ipv6Addr, lladdr: &[u8]) -> Result<(), String> {
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut ts, _) = transport::transport_channel(4096, channel_type).map_err(|e| e.to_string())?;

    let dst = Ipv6Addr::from_str("ff02::1").unwrap();
    let na = gen_neighbor_advert(target_addr, lladdr, &dst)?;
    ts.set_ttl(255).map_err(|e| e.to_string())?;
    ts.send_to(na, dst.into()).map_err(|e| e.to_string())?;

    Ok(())
}

fn gen_neighbor_advert<'a>(ip_addr: &'a Ipv6Addr, lladdr: &'a [u8], dst: &'a Ipv6Addr) -> Result<MutableNeighborAdvertPacket<'a>, String> {
    let packet = vec![0u8; 32];
    let options = [NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: lladdr.to_owned(),
    }];
    let mut na = MutableNeighborAdvertPacket::owned(packet).unwrap();
    na.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
    na.set_icmpv6_code(Icmpv6Codes::NoCode);
    na.set_target_addr(*ip_addr);
    na.set_options(&options[..]);
    na.set_checksum(0xffff);
    let icmpv6_packet = Icmpv6Packet::new(na.packet()).ok_or("Failed to construct ICMPv6Packet")?;
    let checksum = icmpv6::checksum(&icmpv6_packet, &Ipv6Addr::UNSPECIFIED, dst);
    na.set_checksum(checksum);

    Ok(na)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::Packet;

    #[test]
    fn test_gen_neighbor_solicit() {
        let ip_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let lladdr = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let dst = Ipv6Addr::from_str("ff02::1:ff00:0:0:1234").unwrap();
        assert_eq!(
            gen_neighbor_solicit(&ip_addr, &lladdr, &dst).unwrap().packet(),
            &vec![
                0x87, 0x00, 0x68, 0x67,
                0x00, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        );
    }

    #[test]
    fn test_gen_neighbor_advert() {
        let ip_addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let lladdr = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let dst = Ipv6Addr::from_str("ff02::1:ff00:0:0:1234").unwrap();
        assert_eq!(
            gen_neighbor_advert(&ip_addr, &lladdr, &dst).unwrap().packet(),
            &vec![
                0x88, 0x00, 0x67, 0x67,
                0x00, 0x00, 0x00, 0x00,
                0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        );
    }
}
