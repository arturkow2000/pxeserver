use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use crate::tftp::pathutils;
use futures_util::task::{Context, Poll};
use futures_util::{future, FutureExt, StreamExt};
use hyper::service::{make_service_fn, service_fn, Service};
use hyper::{header, Body, Method, Request, Response, StatusCode};
use tokio::fs::{File, OpenOptions};
use tokio_util::codec::{BytesCodec, FramedRead};

pub async fn start(options: &super::Options) {
    if let Some(root) = options.tftp_root.clone() {
        let config = Arc::new(Config { root });

        let make_service = make_service_fn(move |_| {
            let config = Arc::clone(&config);

            let service = service_fn(move |req| {
                let config = Arc::clone(&config);
                Server { config }.serve(req).map(Ok::<_, hyper::Error>)
            });

            future::ok::<_, hyper::Error>(service)
        });

        if let Err(e) =
            hyper::Server::bind(&SocketAddr::from((options.server_ip, options.http_port)))
                .serve(make_service)
                .await
        {
            error!("{}", e)
        }
    }
}

#[derive(Debug)]
struct Config {
    pub root: PathBuf,
}

#[derive(Debug)]
struct Server {
    pub config: Arc<Config>,
}

impl Server {
    async fn serve(self, req: Request<Body>) -> Response<Body> {
        if req.method() == Method::GET {
            match self.serve_file(req.uri().path()).await {
                Ok(response) => response,
                Err(e) => {
                    error!("{}", e);
                    self.respond_404().await
                }
            }
        } else {
            error!("unsupported method {}", req.method());
            self.respond_404().await
        }
    }

    async fn respond_404(&self) -> Response<Body> {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()
    }

    async fn serve_file(&self, file_name: &str) -> anyhow::Result<Response<Body>> {
        let file = self.open_file(file_name, false).await?;

        let len = if let Some(metadata) = file.metadata().await.ok() {
            Some(metadata.len())
        } else {
            None
        };

        info!("commencing {} transfer", file_name);

        let codec = BytesCodec::new();
        let stream = FramedRead::new(file, codec).map(|x| x.map(bytes::BytesMut::freeze));
        let body = Body::wrap_stream(stream);
        let mut builder = Response::builder().status(StatusCode::OK);
        if let Some(len) = len {
            builder = builder.header(header::CONTENT_LENGTH, len);
        }

        Ok(builder.body(body).unwrap())
    }

    async fn open_file(&self, file: &str, write: bool) -> anyhow::Result<File> {
        let path = pathutils::append_path(
            self.config.root.as_path(),
            pathutils::convert_path(file)?.as_path(),
        )?;

        Ok(OpenOptions::new()
            .read(!write)
            .write(write)
            .open(path)
            .await?)
    }
}
