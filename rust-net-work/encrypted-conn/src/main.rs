extern crate core;

use std::env::args;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;
use tokio::net::{TcpListener, TcpSocket};
use rand::{CryptoRng, RngCore};
use snow::params::NoiseParams;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {

    if args().len() < 2 {
        println!("need at least one argument - port");
        exit(1)
    }

    // Skip arg 0
    let listen_port = args().skip(1).next().unwrap();
    println!("Listen port: {}", listen_port);

    let handle = tokio::spawn(async move {
        let port = listen_port;
        run_listener(&port).await
    });

    if args().len() < 3 {
        println!("Listening, not connecting...");
        handle.await.expect("failed while waiting for listener task");
        return;
    }

    println!("Peer address provided, connecting...");
    let peer_addr = args().skip(2).next().unwrap();

    connect_to_peer(&peer_addr).await;
}

// If I would like to deterministically generate Key Pari from password, what I could do is:
// - Run the password thorough some PBKDF, to generate symmetric key
// - Use the symmetric key as ad PRNG input to the Keypair generation function

// Option 2:
// - bip?
// - Perhaps there is some simpler version of that, that 3 words would be enough

async fn connect_to_peer(peer_addr: &str) {
    let sock_addr = SocketAddr::from_str(peer_addr).expect("failed to parse addr");
    let mut socket = TcpSocket::new_v4().expect("failed to create socket");
    let mut tcp_stream = socket.connect(sock_addr).await.expect("failed to connect to peer");

    tcp_stream.write_all("HELLO!".as_bytes()).await.expect("Failed to write!");
    tcp_stream.flush().await.expect("failed to flush");

    println!("I WROTE AND I AM OUT!")
}

async fn run_listener(port: &str) { // TODO: some way of cancelation
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await.expect("failed to bind listener");

    // TODO: so how does it work in libp2p? Is every message encrypted?

    loop {
        let (mut stream, addr) = listener.accept().await.expect("failed to accept connection");

        println!("GOT CONNECTION FROM: {}", addr);

        // TODO: this should read continously from this
        let mut msg = String::new();
        stream.read_to_string(&mut msg).await.expect("failed to read");

        println!("GOT MSG: {}", msg);
        // TODO: do some processing
    }
}

fn noise_params() -> NoiseParams {
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

fn generate_noise_keys() -> Result<snow::Keypair> {
    let builder = snow::Builder::new(noise_params());
    let static_key = builder.generate_keypair()?;
    Ok(static_key)
}

fn generate_key_pair() -> ed25519_dalek::Keypair {
    use rand::rngs::OsRng;
    use ed25519_dalek::Signature;

    let mut csprng = OsRng{};
    let keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut csprng);

    println!("{:?}", keypair.public);
    println!("{:?}", keypair.secret);

    return keypair
}

pub struct Context {
    tx: tokio::sync::mpsc::Sender<bool>,
}

impl Context {
    pub async fn stop(&mut self) -> Result<()> {
        self.tx.send(true).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::select;
    use crate::{connect_to_peer, generate_key_pair, run_listener};
    use crate::Result;

    #[test]
    fn test_generate_keys() {
        let keypair = generate_key_pair();


    }

    #[tokio::test]
    async fn test_server() {
        tokio::spawn(async move {
            select! {
                () = run_listener("8888") => {
                    panic!("unexpected listener stopped")
                },
                () = tokio::time::sleep(Duration::from_secs(10)) => {
                    panic!("server timeout reached")
                }
            }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;

        let addr = "127.0.0.1:8888";

        connect_to_peer(addr).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // async fn run_with_timeout(tx: tokio::sync::oneshot::Sender<Result<()>>) {
    //     match tokio::time::timeout(Duration::from_secs(1), run_test(&ctx)).await {
    //         Ok(res) => tx.send(res).unwrap(),
    //         Err(_) => tx.send(Err(String::frow("error waiting for test to finish"))).unwrap(),
    //     };
    //     let _ = ctx.stop().await;
    // }
}
