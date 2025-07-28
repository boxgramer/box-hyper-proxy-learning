use std::net::SocketAddr;

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Bytes, Method, Request};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

type ClientBuilder = hyper::client::conn::http1::Builder;
type ServerBuilder = hyper::server::conn::http1::Builder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    let listener = TcpListener::bind(addr).await?;
    println!("Server listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(e) = ServerBuilder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, hyper::service::service_fn(proxy))
                .with_upgrades()
                .await
            {
                eprintln!("Error serving connection: {}", e);
            }
        });
    }
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
) -> Result<hyper::Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // Here you would implement your proxy logic
    // For now, we just return a simple response
    if Method::CONNECT == req.method() {
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
