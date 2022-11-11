
// TODO: this will be rellay server that will punch UDP holes
// - Accept connections from clients and identify them - some ID/name
// - How do I then connect one client to another?

// TODO: this will have to be deployed on a server that has a public IP address

use std::collections::HashMap;
use std::env::args;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use tracing::{debug, error, info};

// pub struct ClientAddr {
//     pub ip: String,
//     pub port: u16,
// }

type Registry = Arc<Mutex<HashMap<String, SocketAddr>>>;

#[tokio::main]
async fn main() -> Result<()> {

    tracing_subscriber::fmt::init();

    let password = args().skip(1).next().expect("password not provided");

    let registry = Registry::new(Mutex::new(HashMap::new()));

    let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:9999").await?;

    let mut buf = [0; 1024];
    loop {
        let (len, addr) = udp_socket.recv_from(&mut buf).await?;
        info!("{:?} bytes received from {:?}", len, addr);

        let msg = std::str::from_utf8(&buf[..len]).expect("invalid UTF-8");
        debug!(msg, "read message");

        let parts = msg.trim_end().split(" ").collect::<Vec<&str>>();
        debug!(count = parts.len(), "split message");

        if parts.len() != 3 {
            error!("Invalid message, expected 3 parts: {}", msg);
            continue;
        }

        if parts[0] != &password {
            error!("Invalid password: {}", msg);
            continue;
        }

        {
            info!(addr = ?addr, id = parts[1], "registering client");
            let mut reg = registry.lock().expect("failed to lock");
            reg.insert(parts[1].to_string(), addr.clone());

            info!(peer = parts[2], "searching for peer address");
            match reg.get(parts[2]) {
                Some(peer_addr) => {
                    udp_socket.send_to(format!("Addr: {}", peer_addr).as_bytes(), addr).await?;
                }
                None => {
                    udp_socket.send_to(b"NOT_FOUND", addr).await?;
                }
            }
        }
    }


    println!("Hello, world!");

    Ok(())
}
