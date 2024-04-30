use binrw::{BinReaderExt, BinWrite};
use std::{
    env,
    io::{Cursor},
    net::UdpSocket,
};

use dns_starter_rust::message::{
    DnsMessage, DnsQuestion, DnsResourceRecord, DnsResourceRecordData, QueryResponseIndicator,
    QuestionClass, QuestionType,
};

const ENDPOINT: &str = "127.0.0.1:2053";
const CLIENT_ENDPOINT: &str = "127.0.0.1:2054";

fn resolve_question(question: &DnsQuestion, resolver: &str) -> anyhow::Result<DnsResourceRecord> {
    let udp_socket = UdpSocket::bind(CLIENT_ENDPOINT)?;
    udp_socket.connect(resolver)?;
    let mut dns_message = DnsMessage::default();
    dns_message.header.question_count = 1;
    dns_message.questions.push(question.clone());

    let mut output = Cursor::new(Vec::new());
    dns_message.write_be(&mut output)?;
    let data = output.into_inner();
    udp_socket.send(&data)?;

    let mut buf = [0; 512];
    let (size, _) = udp_socket.recv_from(&mut buf)?;

    let dns_reply = Cursor::new(&buf[..size])
        .read_be::<DnsMessage>()
        .expect("expected UDP package header as reply");
    if dns_reply.header.answer_count != 1 {
        anyhow::bail!(
            "Unexpected number of answers: {}",
            dns_reply.header.answer_count
        );
    }
    println!("resolver returned: {dns_reply:?}");

    Ok(dns_reply.resource_records.first().unwrap().clone())
}

fn run_resolver(resolver: &str) -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind(ENDPOINT).expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let dns_query = Cursor::new(&buf[..size])
                    .read_be::<DnsMessage>()
                    .expect("expected UDP package header for request");
                println!("request: {dns_query:?}");

                let mut dns_response = dns_query.clone();
                dns_response
                    .header
                    .flags
                    .set_qr(QueryResponseIndicator::Response);
                dns_response
                    .header
                    .flags2
                    .set_response(if dns_query.header.flags.opcode() == 0 {
                        0
                    } else {
                        4
                    });
                assert_eq!(dns_response.resource_records.len(), 0);

                for question in dns_query.questions.iter() {
                    dns_response
                        .resource_records
                        .push(resolve_question(question, resolver)?);
                    dns_response.header.answer_count += 1;
                }

                let mut output = Cursor::new(Vec::new());
                dns_response.write_be(&mut output).unwrap();
                let response = output.into_inner();
                println!("sending reply: {dns_response:?}");

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(err) => anyhow::bail!(err),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("program arguments: {args:?}");

    if args.len() == 3 {
        assert_eq!(args[1], "--resolver");
        run_resolver(&args[2]).unwrap();
    }

    println!("Listening at: {ENDPOINT}");

    /*
    let data: [u8; 53] = [0x90, 0xdc, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 0x61, 0x62, 0x63, 0x11, 0x6c, 0x6f, 0x6e, 0x67, 0x61, 0x73, 0x73, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x6e, 0x61, 0x6d, 0x65, 3, 0x63, 0x6f, 0x6d, 0, 0, 1, 0, 1, 3, 0x64, 0x65, 0x66, 0xc0, 0x10, 0, 1, 0, 1];
    let x = Cursor::new(data).read_be::<DnsMessage>();
    println!("{x:?}");
    todo!();
    */

    let udp_socket = UdpSocket::bind(ENDPOINT).expect("Failed to bind to address");
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
                dns_response
                    .header
                    .flags2
                    .set_response(if dns_query.header.flags.opcode() == 0 {
                        0
                    } else {
                        4
                    });
                dns_response.header.answer_count = dns_query.questions.len() as u16;

                for question in dns_query.questions.iter() {
                    dns_response.resource_records.push(DnsResourceRecord {
                        name: question.label.clone(),
                        class: QuestionClass::Internet,
                        kind: QuestionType::A,
                        ttl: 60,
                        data: DnsResourceRecordData::A { ip: [8, 8, 8, 8] },
                    });
                }

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
