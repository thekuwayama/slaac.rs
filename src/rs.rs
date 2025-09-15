extern crate anyhow;
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

pub(crate) fn resolve_router_prefix(lladdr: Vec<u8>) -> Result<(Ipv6Addr, u8), String> {
    let channel_type = TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6));
    let (mut ts, mut tr) = transport::transport_channel(4096, channel_type).map_err(|e| e.to_string())?;
    let mut tr = transport::icmpv6_packet_iter(&mut tr);

    let rs = gen_router_solicit(lladdr)?;
    let dst = IpAddr::from_str("ff02::2").unwrap();
    ts.set_ttl(255).map_err(|e| e.to_string())?;
    ts.send_to(rs, dst).map_err(|e| e.to_string())?;

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

fn gen_router_solicit<'a>(lladdr: Vec<u8>) -> Result<MutableRouterSolicitPacket<'a>, String> {
    let packet = vec![0u8; 16];
    let options = [NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: lladdr,
    }];
    let mut rs = MutableRouterSolicitPacket::owned(packet).unwrap();
    rs.set_icmpv6_type(Icmpv6Types::RouterSolicit);
    rs.set_icmpv6_code(Icmpv6Code(0));
    rs.set_options(&options[..]);

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
