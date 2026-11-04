use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::error::Result;

/// Copy bytes in both directions until one side closes.
///
/// The first count is bytes read from `client` (application toward the proxy).
/// The second is bytes read from `upstream` (proxy toward the application).
pub async fn splice_tcp(client: &mut TcpStream, upstream: &mut TcpStream) -> Result<(u64, u64)> {
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let counts = tokio::io::copy_bidirectional(client, upstream).await?;
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    Ok(counts)
}
