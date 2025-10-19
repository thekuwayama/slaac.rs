extern crate anyhow;
extern crate pnet;

use std::convert::TryInto;
use std::net::{Ipv6Addr, IpAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmpv6::{self, Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmpv6::ndp::{Icmpv6Codes, MutableRouterSolicitPacket, NdpOption, NdpOptionTypes, RouterAdvertPacket};
use pnet::packet::icmpv6::ndp::NdpOptionTypes::PrefixInformation;
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};

pub(crate) fn resolve_router_prefix(lladdr: &[u8]) -> Result<(Ipv6Addr, u8), String> {
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut ts, mut tr) = transport::transport_channel(4096, channel_type).map_err(|e| e.to_string())?;
    let mut tr = transport::icmpv6_packet_iter(&mut tr);

    let dst = Ipv6Addr::from_str("ff02::2").unwrap();
    let rs = gen_router_solicit(lladdr, &dst)?;
    ts.set_ttl(255).map_err(|e| e.to_string())?;
    ts.send_to(rs, IpAddr::from(dst)).map_err(|e| e.to_string())?;

    let icmpv6_response = match tr.next_with_timeout(Duration::from_secs(2)) {
        Ok(packet) => match packet {
            Some((res, _)) => res,
            _ => return Err("Failed to receive ICMPv6 packet.".to_string()),
        },
        Err(e) => return Err(e.to_string()),
    };
    if icmpv6_response.get_icmpv6_type() == Icmpv6Types::RouterAdvert{
        return parse_ra(icmpv6_response.packet());
    }

    Err("Failed toreceived RA.".to_string())
}

fn gen_router_solicit<'a>(lladdr: &'a [u8], dst: &'a Ipv6Addr) -> Result<MutableRouterSolicitPacket<'a>, String> {
    let packet = vec![0u8; 32];
    let options = [NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: lladdr.to_owned(),
    }];
    let mut rs = MutableRouterSolicitPacket::owned(packet).unwrap();
    rs.set_icmpv6_type(Icmpv6Types::RouterSolicit);
    rs.set_icmpv6_code(Icmpv6Codes::NoCode);
    rs.set_options(&options[..]);
    rs.set_checksum(0xffff);
    let icmpv6_packet = Icmpv6Packet::new(rs.packet()).ok_or("Failed to construct ICMPv6 Packet")?;
    let checksum = icmpv6::checksum(&icmpv6_packet, &Ipv6Addr::UNSPECIFIED, dst);
    rs.set_checksum(checksum);

    Ok(rs)
}

fn parse_ra(packet: &[u8]) -> Result<(Ipv6Addr, u8), String> {
    let ra = RouterAdvertPacket::owned(packet.to_vec()).ok_or("Failed to parse RA.")?;
    let option = ra.get_options().into_iter().find(|opt| opt.option_type == PrefixInformation).ok_or("Failed to parse RA.")?;
    if option.data.len() >= 32 {
        let prefix: [u8; 16] = option.data[16..32].try_into().ok().ok_or("Failed to parse Prefix Information.")?;
        let prefix_length = option.data[2];
        return Ok((Ipv6Addr::from(prefix), prefix_length));
    }

    Err("Not found IPv6 Prefix Information.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_router_solicit() {
        let lladdr = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let dst = Ipv6Addr::from_str("ff02::1:ff00:0:0:1234").unwrap();
        assert_eq!(
            gen_router_solicit(&lladdr, &dst).unwrap().packet(),
            &vec![
                0x85, 0x00, 0x69, 0x6b,
                0x00, 0x00, 0x00, 0x00,
                0x01, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
        );
    }
}
