mod noise;

extern crate core;

use std::env::args;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use anyhow::Context;
use tokio::net::{TcpListener, TcpSocket};
use snow::params::NoiseParams;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::{App, Arg, Parser, IntoApp};
use tracing::info;
use tracing_subscriber;

pub type Result<T> = anyhow::Result<T>;

// This needs to be 32 bytes
const PSK: &str = "SECRET_SECRET_SECRET_SECRET_SECR";
// const PSK: &str = "i don't care for fidget spinners";

// TODO: next steps:
// - Support WireGuard like protocol (noise conf)
// - Passing trusted keys to the CLI
// - Associating IP/Port with Key?

#[derive(Parser, Debug)]
pub struct Listen {
    #[clap(short, long, default_value = "7010")]
    pub port: String,
    #[clap(short, long, default_value = "0.0.0.0")]
    pub addr: String,
    #[clap(long, forbid_empty_values = true, default_value = "./dev-keys/peer1")]
    pub priv_key_path: PathBuf,
    #[clap(long, forbid_empty_values = true, default_value = "./dev-keys/peer1.pub")]
    pub pub_key_path: PathBuf,
    #[clap(long, forbid_empty_values = true, required = false)]
    pub peer_addr: Option<String>,
    #[clap(long, forbid_empty_values = true, required = false)]
    pub peer_pub_key_path: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub enum SubCommand {
    Listen(Listen),
}

#[derive(Parser, Debug)]
pub struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    let mut app = Opts::into_app();

    tracing_subscriber::fmt::init();

    match opts.subcmd {
        SubCommand::Listen(listen_cmd) => {
            start_peer(listen_cmd).await.expect("failed to start peer")
        }
    }

    Ok(())
}

async fn start_peer(listen: Listen) -> anyhow::Result<()> {
    let keypair = prepare_keypair(&listen.priv_key_path, &listen.pub_key_path).await
        .context("failed to prepare keypair")?;

    let listen_addr = format!("{}:{}", listen.addr, listen.port);

    let listener_keypair = clone_keypair(&keypair);
    let handle = tokio::spawn(async move {
        let addr = listen_addr;
        run_listener(&addr, listener_keypair).await
    });

    if let Some(peer) = listen.peer_addr {
        if listen.peer_pub_key_path.is_none() {
            return Err(anyhow::Error::msg("peer public key path not provided"))
        }
        let peer_key = read_key(&listen.peer_pub_key_path.unwrap()).await?;

        info!(peer_addr = peer.as_str(), "Peer address provided, connecting...");
        connect_to_peer(&peer, keypair, &peer_key).await;
    }

    handle.await.context("failed in listener handle")?;

    Ok(())
}

async fn prepare_keypair(priv_key_path: &PathBuf, pub_key_path: &PathBuf) -> anyhow::Result<snow::Keypair> {
    if !priv_key_path.exists() || !pub_key_path.exists() {
        println!("Keys not found, generating...");
        let keypair = generate_noise_keys().context("failed to generate key pair")?;

        fs::write(priv_key_path, &keypair.private).await.context("failed to save private key")?;
        fs::write(pub_key_path, &keypair.public).await.context("failed to save public key")?;
        Ok(keypair)
    } else {
        let privkey = fs::read(priv_key_path).await.context("failed to read private key")?;
        let pubkey = fs::read(pub_key_path).await.context("failed to read public key")?;

        Ok(snow::Keypair { private: privkey, public: pubkey })
    }
}

async fn read_key(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let bytes = fs::read(path).await.context("failed to read key")?;
    Ok(bytes)
}

// Keypair does not implement 'Clone' trait
fn clone_keypair(keypair: &snow::Keypair) -> snow::Keypair {
    return snow::Keypair {
        public: keypair.public.clone(),
        private: keypair.private.clone(),
    };
}

// If I would like to deterministically generate Key Pari from password, what I could do is:
// - Run the password thorough some PBKDF, to generate symmetric key
// - Use the symmetric key as ad PRNG input to the Keypair generation function

// Option 2:
// - bip?
// - Perhaps there is some simpler version of that, that 3 words would be enough

async fn connect_to_peer(peer_addr: &str, keypair: snow::Keypair, peer_pub_key: &[u8]) {
    let mut buf = vec![0u8; 65535];

    let sock_addr = SocketAddr::from_str(peer_addr).expect("failed to parse addr");
    let socket = TcpSocket::new_v4().expect("failed to create socket");
    let mut tcp_stream = socket.connect(sock_addr).await.expect("failed to connect to peer");

    let mut noise = initiator_handshake(&mut tcp_stream, keypair, &mut buf, peer_pub_key).await
        .expect("failed to run the handshake");

    for i in 0..10 {
        println!("Sending msg {}", i);
        let len = noise.write_message(b"HACK THE PLANET", &mut buf).unwrap();
        send(&mut tcp_stream, &buf[..len]).await;
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    // tcp_stream.write_all("HELLO!".as_bytes()).await.expect("Failed to write!");
    // tcp_stream.flush().await.expect("failed to flush");

    // TODO: read something and return it

    println!("I WROTE AND I AM OUT!")
}

async fn initiator_handshake(tcp_stream: &mut tokio::net::TcpStream, keypair: snow::Keypair,buf:  &mut [u8], remote_pub: &[u8]) -> Result<snow::TransportState> {
    let builder: snow::Builder<'_> = snow::Builder::new(noise_params())
        .local_private_key(&keypair.private)
        .remote_public_key(remote_pub);
    let mut noise =
        builder
        // builder.local_private_key(&keypair.private)
            .psk(2, PSK.as_bytes())

            .build_initiator().unwrap();

    // So this is handled internally - the struct noise maintains the state of the handshake,
    // therefore it knows what to write to the buffer next.
    // -> e - sending the ephemeral key
    let len = noise.write_message(&[], buf).unwrap();
    let pub_ephemeral_key = base64::encode(&buf[..len]);
    println!("Init msg with pub key: {:?}", pub_ephemeral_key);

    // -> e
    send(tcp_stream, &buf[..len]).await;

    // <- e, ee, s, es
    let msg = recv(tcp_stream).await.expect("failed to received after init");
    println!("Got after init: {}", base64::encode(&msg));
    noise.read_message(&msg, buf).unwrap();

    // -> s, se
    // let len = noise.write_message(&[], buf).unwrap();
    // println!("Sending next msg: {}", base64::encode(&buf[..len]));
    // send(tcp_stream, &buf[..len]).await;

    let noise = noise.into_transport_mode().unwrap();
    println!("session established client side...");

    Ok(noise)
}

async fn run_listener(addr: &str, keypair: snow::Keypair) { // TODO: some way of cancelation
    info!(addr, "Starting listener");

    let listener = TcpListener::bind(addr)
        .await.expect("failed to bind listener");

    loop {
        let (stream, addr) = listener.accept().await.expect("failed to accept connection");

        let kp = clone_keypair(&keypair);
        tokio::spawn(async move {
            handle_connection(kp, addr, stream).await;
        });
    }
}

async fn handle_connection(keypair: snow::Keypair, peer: SocketAddr, mut stream: tokio::net::TcpStream) {
    let mut buf = vec![0u8; 65535];

    println!("GOT CONNECTION FROM: {}", peer);

    let mut noise = responder_handshake(&mut stream, keypair, &mut buf)
        .await
        .expect("failed to perform responder handshake");

    // TODO: change this to some proper reading
    // TODO: if you read 0 bytes, this means that the other side disconnected and you should break
    while let Ok(msg) = recv(&mut stream).await {
        let len = noise.read_message(&msg, &mut buf).unwrap();
        println!("client said: {}", String::from_utf8_lossy(&buf[..len]));
    }

    // TODO: this should read continously from this
    // let mut msg = String::new();
    // stream.read_to_string(&mut msg).await.expect("failed to read");

    // println!("GOT MSG: {}", msg);
    // TODO: do some processing
}

// TODO: do not panic on errors
async fn responder_handshake(stream: &mut tokio::net::TcpStream, keypair: snow::Keypair, buf: &mut [u8]) -> Result<snow::TransportState> {
    let builder: snow::Builder<'_> = snow::Builder::new(noise_params());
    // TODO: do I need remote pub here too?
    let mut noise =
        builder.local_private_key(&keypair.private)
            // .remote_public_key()  // TODO: here need to set the remote public key of the peer
            .psk(2, PSK.as_bytes())
            .build_responder().unwrap();

    // TODO: move to function
    let init_msg = recv(stream).await.expect("failed to receive init msg");
    println!("GOT INIT MSG: {}", base64::encode(&init_msg));

    // <- e, es, s, ss
    noise.read_message(&init_msg, buf)
        .expect("failed to read init msg");

    // -> e, ee, se, psk
    let len = noise.write_message(&[0u8; 0], buf).unwrap();
    println!("SENDING BACK {} bytes: {}", len, base64::encode(&buf[..len]));
    // println!("BUFF AFTER: {:?}", &buf[len-5..len+10]);
    send(stream, &buf[..len]).await;

    // <- s, se
    // let next_msg = recv(stream).await.expect("failed to received next");
    // println!("GOT NEXT MSG: {}", base64::encode(&next_msg));
    // noise.read_message(&next_msg, buf).unwrap();

    // Transition the state machine into transport mode now that the handshake is complete.
    let noise = noise.into_transport_mode().unwrap();

    println!("Session established, server side...");

    Ok(noise)
}

fn noise_params() -> NoiseParams {
    // So the handshake patterns are different in WireGuard implementation and in the Example
    // - IK
    // - XX

    // psk2 - means that pre-shared key is on position (?) 2?

    // Wireguard
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap()

    // let param = NoiseParams{
    //
    // }


    // Example
    // "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

fn generate_noise_keys() -> Result<snow::Keypair> {
    let builder = snow::Builder::new(noise_params());
    let static_key = builder.generate_keypair()?;
    // snow::params::NoiseParams{}
    Ok(static_key)
}

// fn generate_key_pair() -> ed25519_dalek::Keypair {
//     use rand::rngs::OsRng;
//     use ed25519_dalek::Signature;
//
//     let mut csprng = OsRng {};
//     let keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut csprng);
//
//     println!("{:?}", keypair.public);
//     println!("{:?}", keypair.secret);
//
//     return keypair;
// }

/// Hyper-basic stream transport receiver. 16-bit BE size followed by payload.
async fn recv(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    // println!("Reading...");
    let mut msg_len_buf = [0u8; 2];
    stream.read_exact(&mut msg_len_buf).await?;
    let msg_len = ((msg_len_buf[0] as usize) << 8) + (msg_len_buf[1] as usize);
    // println!("Expected msg len: {}", msg_len);
    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg[..]).await?;
    Ok(msg)
}

/// Hyper-basic stream transport sender. 16-bit BE size followed by payload.
async fn send(stream: &mut tokio::net::TcpStream, buf: &[u8]) {
    let msg_len_buf = [(buf.len() >> 8) as u8, (buf.len() & 0xff) as u8];
    // println!("MSG LEN BUFF: {:?}", msg_len_buf);
    stream.write_all(&msg_len_buf).await.unwrap();
    // println!("BUFF LEN: {}", buf.len());
    stream.write_all(buf).await.unwrap();
}

// pub struct Context {
//     tx: tokio::sync::mpsc::Sender<bool>,
// }
//
// impl Context {
//     pub async fn stop(&mut self) -> Result<()> {
//         self.tx.send(true).await?;
//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::select;
    use crate::{
        connect_to_peer,
        // generate_key_pair,
        generate_noise_keys,
        run_listener};

    // #[test]
    // fn test_generate_keys() {
    //     let keypair = generate_key_pair();
    // }

    #[tokio::test]
    async fn test_server() {
        let server_keys = generate_noise_keys().expect("failed to generate server keys");
        let client_keys = generate_noise_keys().expect("failed to generate client keys");

        let server_pub = server_keys.public.clone();

        tokio::spawn(async move {
            select! {
                () = run_listener("0.0.0.0:8888", server_keys) => {
                    panic!("unexpected listener stopped")
                },
                () = tokio::time::sleep(Duration::from_secs(10)) => {
                    panic!("server timeout reached")
                }
            }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;

        let addr = "127.0.0.1:8888";

        connect_to_peer(addr, client_keys, &server_pub).await;
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
