use std::net::Ipv4Addr;

pub fn belongs(address: Ipv4Addr, subnet: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    let address = Into::<u32>::into(address);
    let subnet = Into::<u32>::into(subnet);
    let subnet_mask = Into::<u32>::into(subnet_mask);

    assert_eq!(subnet & subnet_mask, subnet);

    address & subnet_mask == subnet
}
