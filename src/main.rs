use binrw::{BinReaderExt, BinWrite};
use std::{io::Cursor, net::UdpSocket};

use dns_starter_rust::message::{
    DnsMessage, DnsResourceRecord, DnsResourceRecordData, QueryResponseIndicator, QuestionClass,
    QuestionType,
};

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
                dns_response
                    .header
                    .flags
                    .set_qr(QueryResponseIndicator::Response);
                dns_response.header.arcount = 0;
                dns_response.header.flags2.set_response(if dns_query.header.flags.opcode() == 0 { 0} else {4});
                dns_response.header.answer_count = 1;
                dns_response.resource_records.push(DnsResourceRecord {
                    name: dns_query.questions.first().unwrap().label.clone(),
                    class: QuestionClass::Internet,
                    kind: QuestionType::A,
                    ttl: 60,
                    data: DnsResourceRecordData::A { ip: [8, 8, 8, 8] },
                });

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
