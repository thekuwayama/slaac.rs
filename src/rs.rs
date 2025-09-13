extern crate pnet;

use std::convert::TryInto;
use std::net::{Ipv6Addr, IpAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmpv6::{Icmpv6Types, Icmpv6Code};
use pnet::packet::icmpv6::ndp::{MutableRouterSolicitPacket, NdpOption, NdpOptionTypes, RouterAdvertPacket};
use pnet::packet::icmpv6::ndp::NdpOptionTypes::PrefixInformation;
use pnet::transport::{self, TransportChannelType, TransportProtocol};

pub fn resolve_router_prefix() -> Result<IpAddr, String> {
    let (mut ts, mut tr) = transport::transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .map_err(|e| e.to_string())?;
    let mut tr = transport::icmpv6_packet_iter(&mut tr);
    
    let router_solicit = gen_router_solicit();
    let dst = IpAddr::from_str("ff02::2").unwrap();
    ts.send_to(router_solicit, dst).map_err(|e| e.to_string())?;
    let icmpv6_response = match tr.next_with_timeout(Duration::from_secs(10)) {
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

fn gen_router_solicit<'a>() -> MutableRouterSolicitPacket<'a> {
    let packet = [0u8; 16];
    let options = [NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }];
    let mut rs = MutableRouterSolicitPacket::owned(packet.to_vec()).unwrap();
    rs.set_icmpv6_type(Icmpv6Types::RouterSolicit);
    rs.set_icmpv6_code(Icmpv6Code(0));
    rs.set_options(&options[..]);
    rs
}

fn parse_ra(packet: &[u8]) -> Result<IpAddr, String> {
    let ra = RouterAdvertPacket::owned(packet.to_vec()).ok_or("Failed to parse RA.")?;
    let option = ra.get_options().into_iter().find(|opt| opt.option_type == PrefixInformation).ok_or("Failed to parse RA.")?;
    if option.data.len() >= 30 {
        let prefix: [u8; 16] = option.data[14..30].try_into().ok().ok_or("Failed to parse Prefix Information.")?;
        return Ok(IpAddr::V6(Ipv6Addr::from(prefix)));
    }

    Err("Not found IPv6 Prefix Information.".to_string())
}
