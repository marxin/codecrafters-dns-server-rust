use binrw::{BinReaderExt, BinWrite};
use std::{io::Cursor, net::UdpSocket};

use dns_starter_rust::message::{DnsMessage, QueryResponseIndicator};

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
                let dns_query = Cursor::new(&buf[..size])
                    .read_be::<DnsMessage>()
                    .expect("expected UDP package header for request");
                println!("request: {dns_query:?}");

                let mut dns_response = dns_query.clone();
                dns_response.header.id = 1234;
                dns_response
                    .header
                    .flags
                    .set_qr(QueryResponseIndicator::Response);
                dns_response.header.arcount = 0;

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
