use core::str::FromStr;
use std::{borrow::ToOwned, vec, vec::Vec};

use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, Medium},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address},
};
use virtio_net::get_device;

const IP: &str = "10.0.2.15"; // QEMU user networking default IP
const GATEWAY: &str = "10.0.2.2"; // QEMU user networking gateway
const PORT: u16 = 5555;

fn main() {
    test_echo_server();
}

fn test_echo_server() {
    let mut device = get_device();

    if device.capabilities().medium != Medium::Ethernet {
        panic!("This implementation only supports virtio-net which is an ethernet device");
    }

    let hardware_addr = HardwareAddress::Ethernet(device.mac_address());

    // Create interface
    let mut config = Config::new(hardware_addr);
    config.random_seed = 0x2333;

    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::from_str(IP).unwrap(), 24))
            .unwrap();
    });

    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::from_str(GATEWAY).unwrap())
        .unwrap();

    // Create sockets
    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 1024]);
    let tcp_socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    println!("start a echo server...");
    let mut tcp_active = false;
    loop {
        let timestamp = Instant::now();

        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if !socket.is_open() {
            println!("listening on port {}...", PORT);
            socket.listen(PORT).unwrap();
        }

        if socket.is_active() && !tcp_active {
            println!("tcp:{} connected", PORT);
        } else if !socket.is_active() && tcp_active {
            println!("tcp:{} disconnected", PORT);
        }
        tcp_active = socket.is_active();

        if socket.may_recv() {
            let data = socket
                .recv(|buffer| {
                    let recvd_len = buffer.len();
                    if !buffer.is_empty() {
                        println!("tcp:{} recv {} bytes: {:?}", PORT, recvd_len, buffer);
                        let lines = buffer
                            .split(|&b| b == b'\n')
                            .map(ToOwned::to_owned)
                            .collect::<Vec<_>>();
                        let data = lines.join(&b'\n');
                        (recvd_len, data)
                    } else {
                        (0, vec![])
                    }
                })
                .unwrap();
            if socket.can_send() && !data.is_empty() {
                println!("tcp:{} send data: {:?}", PORT, data);
                socket.send_slice(&data[..]).unwrap();
            }
        } else if socket.may_send() {
            println!("tcp:{} close", PORT);
            socket.close();
        }
    }
}
