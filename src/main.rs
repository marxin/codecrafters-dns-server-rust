use binrw::{BinReaderExt, BinWrite, BinWriterExt};
use std::{io::Cursor, net::UdpSocket};

use dns_starter_rust::message::{DnsHeader, QueryResponseIndicator};

fn main() {
    let endpoint = "127.0.0.1:2053";
    println!("Listening at: {endpoint}");

    let udp_socket = UdpSocket::bind(endpoint).expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!(
                    "Received {} bytes from {}: {:x?}",
                    size,
                    source,
                    &buf[..size]
                );
                let dns_header = Cursor::new(&buf[..size])
                    .read_be::<DnsHeader>()
                    .expect("expected UDP package header for request");
                println!("request: {dns_header:?}");

                let mut dns_response = DnsHeader::default();
                dns_response.id = 1234;
                dns_response.flags.set_qr(QueryResponseIndicator::Response);
                println!("response: {dns_response:?}");

                let mut output = Cursor::new(Vec::new());
                dns_response.write_be(&mut output).unwrap();
                let response = output.into_inner();

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
