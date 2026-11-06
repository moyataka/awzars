use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Request {
    pub headers: String,
    pub parameters: HashMap<String, String>,
}

pub async fn serve_once(body: &str, status: &str) -> (String, tokio::task::JoinHandle<Request>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let (headers, body) = loop {
                assert!(socket.read_buf(&mut request).await.unwrap() > 0);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break (
                            headers.to_owned(),
                            request[end + 4..end + 4 + length].to_vec(),
                        );
                    }
                }
            };
            socket.write_all(response.as_bytes()).await.unwrap();
            Request {
                headers,
                parameters: url::form_urlencoded::parse(&body).into_owned().collect(),
            }
        })
        .await
        .expect("mock STS request timed out")
    });
    (endpoint, task)
}
