use std::{fs, net::SocketAddr, path::Path, sync::Arc};

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Bytes, Method, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

type ClientBuilder = hyper::client::conn::http1::Builder;
type ServerBuilder = hyper::server::conn::http1::Builder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_path = Path::new("cert/root_ca.crt");
    let key_path = Path::new("cert/root_ca.key");

    if !cert_path.exists() || !key_path.exists() {
        return Err("Certificate or key file does not exist".into());
    }
    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;

    let cert_root = CertificateDer::from_pem_slice(&cert_pem)?;

    let key_root = PrivateKeyDer::from_pem_slice(&key_pem)?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_root.clone()], key_root.clone_key())?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    let listener = TcpListener::bind(addr).await?;
    println!("Server listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();

        tokio::task::spawn(async move {
            let service = hyper::service::service_fn(proxy);
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
            {
                eprintln!("Error in connection: {}", e);
            }
        });
    }
}
async fn is_tls_check(stream: &TcpStream) -> Result<bool, std::io::Error> {
    let mut buff = [0u8; 5];
    match stream.peek(&mut buff).await {
        Ok(5) => {
            println!("Peeked 5 bytes: {:?}", &buff);
            // Check if the first byte is 0x16 (TLS handshake)
            Ok(buff.starts_with(b"\x16\x03"))
        } // TLS handshake starts with 0x16
        Ok(0) => Ok(false), // Connection closed by peer
        Ok(_) => Ok(false), // Connection is open
        Err(e) => Err(e),   // Error peeking stream
    }
}
async fn is_connect(stream: &TcpStream) -> Result<bool, std::io::Error> {
    let mut buff = [0u8; 7];
    match stream.peek(&mut buff).await {
        Ok(7) => Ok(buff.starts_with(b"CONNECT")), // CONNECT request starts with "CONNECT"
        Ok(0) => Ok(false),                        // Connection closed by peer
        Ok(_) => Ok(false),                        // Connection is open
        Err(e) => Err(e),                          // Error peeking stream
    }
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
) -> Result<hyper::Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Here you would implement your proxy logic
    // For now, we just return a simple response
    //
    if Method::CONNECT == req.method() {
        println!("CONNECT request received: ");
        if let Some(addr) = host_addr(req.uri()) {
            println!("Connecting to {}", addr);
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let mut server = TcpStream::connect(addr).await.unwrap();
                        let mut upgraded_io = TokioIo::new(upgraded);

                        let (from_client, from_server) =
                            tokio::io::copy_bidirectional(&mut upgraded_io, &mut server)
                                .await
                                .unwrap();
                        println!(
                            "client wrote {} bytes and received {} bytes",
                            from_client, from_server
                        );
                    }
                    Err(e) => eprintln!("Failed to upgrade connection: {}", e),
                }
            });
        } else {
            return Ok(hyper::Response::new(empty()));
        }
        return Ok(hyper::Response::new(full("you connect to using https")));
    } else {
        let host = req.uri().host().unwrap_or("unknown");
        let port = req.uri().port_u16().unwrap_or(80);
        println!("Proxying request to {}:{}", host, port);
        let stream = TcpStream::connect((host, port)).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = ClientBuilder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake::<_, Full<Bytes>>(io)
            .await?;

        tokio::task::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("Error in connection: {}", e);
            }
        });
        let req = interception(req).await?;
        let response = sender.send_request(req).await?;
        return Ok(response.map(|body| body.boxed()));
    }
}
fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

fn full(str: &'static str) -> BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(str)).map_err(|e| match e {}).boxed()
}
fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

async fn interception(
    req: Request<hyper::body::Incoming>,
) -> Result<Request<Full<Bytes>>, hyper::Error> {
    // Here you can modify the request if needed

    println!("Intercepting method: {} , {}", req.method(), req.uri());
    for (name, value) in req.headers().iter() {
        println!("Header: {}: {:?}", name, value);
    }
    let (mut parts, body) = req.into_parts();
    let bytes = body.collect().await?.to_bytes();

    // parts.method = Method::POST; // Example modification
    println!("parts: {:?}", parts);
    println!("Body: {:?}", bytes);
    println!("{}", String::from_utf8_lossy(&bytes));

    let new_req = Request::from_parts(parts, Full::new(bytes));
    Ok(new_req)
}
