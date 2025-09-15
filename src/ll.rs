use anyhow::Result;
use pnet::datalink;

pub(crate) fn get(iface_name: &str) -> Result<Vec<u8>, String> {
    let res = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && iface.name == iface_name)
        .ok_or(format!("Not found {} network interface.", iface_name))?
        .mac
        .ok_or(format!("Not found {} mac address.", iface_name))?
        .octets()
        .to_vec();

    Ok(res)
}
