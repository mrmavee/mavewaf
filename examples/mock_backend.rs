use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn hello(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let (body, status) = match path {
        "/" => (Bytes::from("Hello from Mock Backend!"), StatusCode::OK),
        "/login" => (Bytes::from("Login Page"), StatusCode::OK),
        "/admin" => (Bytes::from("Admin Dashboard"), StatusCode::OK),
        _ => (Bytes::from("404 Not Found"), StatusCode::NOT_FOUND),
    };

    let response = Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(body))
        .unwrap();

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 9000));

    let listener = TcpListener::bind(addr).await?;
    println!("Mock backend listening on http://{addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(hello))
                .await
            {
                eprintln!("Error serving connection: {err:?}");
            }
        });
    }
}
