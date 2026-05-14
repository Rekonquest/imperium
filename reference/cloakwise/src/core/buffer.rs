//! Zero-Copy Buffer Pool
//!
//! Shared buffer management for all protocols, eliminating:
//! - Per-protocol buffer allocation
//! - Redundant memory copies between layers
//! - Memory fragmentation from frequent alloc/dealloc
//!
//! Traffic moves from SDR/Network interface to encryption engine
//! without being re-copied in RAM.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;

/// Default buffer size (16KB - optimal for most MTUs)
const DEFAULT_BUFFER_SIZE: usize = 16384;

/// Maximum buffer size (1MB)
const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// Pool size (number of pre-allocated buffers)
const POOL_SIZE: usize = 256;

/// Zero-copy buffer pool
pub struct BufferPool {
    /// Available buffers
    buffers: Mutex<Vec<BytesMut>>,

    /// Buffer size
    buffer_size: usize,

    /// Total allocations
    allocations: AtomicUsize,

    /// Total releases
    releases: AtomicUsize,

    /// Peak concurrent usage
    peak_usage: AtomicUsize,

    /// Current usage
    current_usage: AtomicUsize,
}

impl BufferPool {
    /// Create a new buffer pool with default settings
    pub fn new() -> Self {
        Self::with_capacity(POOL_SIZE, DEFAULT_BUFFER_SIZE)
    }

    /// Create a buffer pool with custom capacity and buffer size
    pub fn with_capacity(pool_size: usize, buffer_size: usize) -> Self {
        let buffer_size = buffer_size.min(MAX_BUFFER_SIZE);
        let mut buffers = Vec::with_capacity(pool_size);

        // Pre-allocate buffers
        for _ in 0..pool_size {
            buffers.push(BytesMut::with_capacity(buffer_size));
        }

        Self {
            buffers: Mutex::new(buffers),
            buffer_size,
            allocations: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            current_usage: AtomicUsize::new(0),
        }
    }

    /// Acquire a buffer from the pool
    pub fn acquire(&self) -> PooledBuffer<'_> {
        let mut pool = self.buffers.lock();

        let buffer = pool.pop().unwrap_or_else(|| {
            // Pool exhausted, allocate new
            self.allocations.fetch_add(1, Ordering::Relaxed);
            BytesMut::with_capacity(self.buffer_size)
        });

        let current = self.current_usage.fetch_add(1, Ordering::Relaxed) + 1;
        let peak = self.peak_usage.load(Ordering::Relaxed);
        if current > peak {
            self.peak_usage.store(current, Ordering::Relaxed);
        }

        PooledBuffer {
            inner: buffer,
            pool: self,
        }
    }

    /// Release a buffer back to the pool
    fn release(&self, mut buffer: BytesMut) {
        buffer.clear();

        let mut pool = self.buffers.lock();
        if pool.len() < POOL_SIZE {
            pool.push(buffer);
        }
        // If pool is full, buffer is dropped

        self.releases.fetch_add(1, Ordering::Relaxed);
        self.current_usage.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            total_allocations: self.allocations.load(Ordering::Relaxed),
            total_releases: self.releases.load(Ordering::Relaxed),
            peak_usage: self.peak_usage.load(Ordering::Relaxed),
            current_usage: self.current_usage.load(Ordering::Relaxed),
            pool_size: self.buffers.lock().len(),
            buffer_size: self.buffer_size,
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about buffer pool usage
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_allocations: usize,
    pub total_releases: usize,
    pub peak_usage: usize,
    pub current_usage: usize,
    pub pool_size: usize,
    pub buffer_size: usize,
}

/// A buffer acquired from the pool - automatically returned on drop
pub struct PooledBuffer<'a> {
    inner: BytesMut,
    pool: &'a BufferPool,
}

impl<'a> PooledBuffer<'a> {
    /// Get the inner BytesMut
    pub fn inner(&self) -> &BytesMut {
        &self.inner
    }

    /// Get mutable access to inner BytesMut
    pub fn inner_mut(&mut self) -> &mut BytesMut {
        &mut self.inner
    }

    /// Freeze into immutable Bytes (detaches from pool)
    pub fn freeze(mut self) -> Bytes {
        let bytes = std::mem::take(&mut self.inner);
        std::mem::forget(self); // Don't return to pool
        bytes.freeze()
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.inner.capacity() - self.inner.len()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Write bytes to buffer
    pub fn put_slice(&mut self, src: &[u8]) {
        self.inner.put_slice(src);
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'a> Drop for PooledBuffer<'a> {
    fn drop(&mut self) {
        let buffer = std::mem::take(&mut self.inner);
        if buffer.capacity() > 0 {
            self.pool.release(buffer);
        }
    }
}

impl<'a> AsRef<[u8]> for PooledBuffer<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl<'a> AsMut<[u8]> for PooledBuffer<'a> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

/// Global shared buffer pool
pub static BUFFER_POOL: once_cell::sync::Lazy<Arc<BufferPool>> =
    once_cell::sync::Lazy::new(|| Arc::new(BufferPool::new()));

/// Acquire a buffer from the global pool
pub fn acquire_buffer() -> PooledBuffer<'static> {
    BUFFER_POOL.acquire()
}

/// Zero-copy packet for protocol processing
#[derive(Debug)]
pub struct Packet {
    /// Raw packet data
    data: Bytes,

    /// Offset into data where payload starts (after headers)
    payload_offset: usize,

    /// Packet metadata
    pub metadata: PacketMetadata,
}

impl Packet {
    /// Create from raw bytes
    pub fn from_bytes(data: Bytes) -> Self {
        Self {
            data,
            payload_offset: 0,
            metadata: PacketMetadata::default(),
        }
    }

    /// Create with specific payload offset
    pub fn with_offset(data: Bytes, payload_offset: usize) -> Self {
        Self {
            data,
            payload_offset,
            metadata: PacketMetadata::default(),
        }
    }

    /// Get raw packet data
    pub fn raw(&self) -> &[u8] {
        &self.data
    }

    /// Get payload (data after headers)
    pub fn payload(&self) -> &[u8] {
        &self.data[self.payload_offset..]
    }

    /// Get header portion
    pub fn header(&self) -> &[u8] {
        &self.data[..self.payload_offset]
    }

    /// Total length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Payload length
    pub fn payload_len(&self) -> usize {
        self.data.len().saturating_sub(self.payload_offset)
    }
}

/// Packet metadata for analysis
#[derive(Debug, Clone, Default)]
pub struct PacketMetadata {
    /// Timestamp when received
    pub timestamp: Option<std::time::Instant>,

    /// Source address
    pub src_addr: Option<std::net::SocketAddr>,

    /// Destination address
    pub dst_addr: Option<std::net::SocketAddr>,

    /// Protocol identifier
    pub protocol: Option<String>,

    /// Whether this packet was encrypted
    pub encrypted: bool,

    /// Whether this packet was padded
    pub padded: bool,

    /// Original size before padding
    pub original_size: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new();

        // Acquire multiple buffers
        let mut buffers: Vec<_> = (0..10).map(|_| pool.acquire()).collect();

        // Write to buffers
        for (i, buf) in buffers.iter_mut().enumerate() {
            buf.put_slice(&[i as u8; 100]);
        }

        // Release all
        drop(buffers);

        // Check stats
        let stats = pool.stats();
        assert_eq!(stats.current_usage, 0);
        assert_eq!(stats.peak_usage, 10);
    }

    #[test]
    fn test_zero_copy() {
        let pool = BufferPool::new();
        let mut buf = pool.acquire();

        // Write data
        buf.put_slice(b"Hello, World!");

        // Freeze to Bytes (zero-copy)
        let bytes = buf.freeze();
        assert_eq!(&bytes[..], b"Hello, World!");
    }

    #[test]
    fn test_packet() {
        let data = Bytes::from_static(b"\x00\x01\x02\x03Hello, World!");
        let packet = Packet::with_offset(data, 4);

        assert_eq!(packet.header(), &[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(packet.payload(), b"Hello, World!");
    }
}
