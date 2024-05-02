use binrw::{BinRead, BinResult, BinWrite};
use modular_bitfield::prelude::*;
use std::io::SeekFrom;

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
pub enum QueryResponseIndicator {
    Query,
    Response,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
pub enum AuthoritativeAnswer {
    Other,
    Owns,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
pub enum Truncation {
    No,
    LargerThan512,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
pub enum RecursionDesired {
    NonRecursive,
    Recursive,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
pub enum RecursionAvailable {
    NotAvailable,
    Available,
}

#[bitfield]
#[derive(BinRead, BinWrite, Debug, Default, Clone, Copy)]
#[br(map = Self::from_bytes)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct DnsHeaderFlags {
    /// Recursion Desired (RD) Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub recursion_desired: RecursionDesired,
    /// Truncation (TC) 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub truncation: Truncation,
    /// Authoritative Answer (AA) 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub authoritative: AuthoritativeAnswer,
    /// Operation Code (OPCODE)	Specifies the kind of query in a message.
    pub opcode: B4,
    /// Query/Response Indicator (QR). 1 for a reply packet, 0 for a question packet.
    pub qr: QueryResponseIndicator,
}

#[bitfield]
#[derive(BinRead, BinWrite, Debug, Default, Clone, Copy)]
#[br(map = Self::from_bytes)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct DnsHeaderFlags2 {
    /// Response Code (RCODE) Response code indicating the status of the response.
    pub response: B4,
    /// Reserved (Z) Used by DNSSEC queries. At inception, it was reserved for future use.
    #[skip]
    __: B3,
    /// Recursion Available (RA) Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: RecursionAvailable,
}

#[derive(BinRead, BinWrite, Debug, Default, Clone)]
pub struct DnsHeader {
    /// Packet Identifier (ID)A random ID assigned to query packets. Response packets must reply with the same ID.
    pub id: u16,

    pub flags: DnsHeaderFlags,

    pub flags2: DnsHeaderFlags2,

    /// Question Count (QDCOUNT) Number of questions in the Question section.
    pub question_count: u16,

    /// Answer Record Count (ANCOUNT) Number of records in the Answer section.
    pub answer_count: u16,

    /// Authority Record Count (NSCOUNT) Number of records in the Authority section.
    pub nscount: u16,

    /// Additional Record Count (ARCOUNT) Number of records in the Additional section.
    pub arcount: u16,
}

#[binrw::parser(reader, endian)]
fn parse_labels() -> BinResult<Vec<String>> {
    let mut labels = Vec::new();

    loop {
        let mut length = [0u8; 1];
        reader.read_exact(&mut length)?;
        const OFFSET_MASK: u8 = 0b1100_0000;
        if length[0] & OFFSET_MASK != 0 {
            let mut offset = ((length[0] & (!OFFSET_MASK)) as u64) << 8;
            reader.read_exact(&mut length)?;
            offset += length[0] as u64;
            let current_position = reader.stream_position()?;
            reader.seek(SeekFrom::Start(offset))?;
            let offset_labels = parse_labels(reader, endian, ())?;
            labels.extend(offset_labels);
            reader.seek(SeekFrom::Start(current_position))?;
            break;
        }

        let label_length = length[0] as usize;
        if label_length == 0 {
            break;
        }

        let mut data = vec![0u8; label_length];
        reader.read_exact(&mut data)?;
        // TODO
        labels.push(String::from_utf8(data).unwrap());
    }

    Ok(labels)
}

#[binrw::writer(writer)]
fn write_labels(labels: &Vec<String>) -> BinResult<()> {
    for part in labels {
        writer.write_all(&[part.len() as u8])?;
        writer.write_all(part.as_bytes())?;
    }
    writer.write_all(&[0u8])?;

    Ok(())
}

#[derive(BinRead, BinWrite, Debug, Clone, Default)]
pub struct DnsLabel {
    #[br(parse_with = parse_labels)]
    #[bw(write_with = write_labels)]
    labels: Vec<String>,
}

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(repr = u16)]
pub enum QuestionType {
    A = 1,
    NS = 2,
    CNAME = 5,
}

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(repr = u16)]
pub enum QuestionClass {
    Internet = 1,
}

#[derive(BinRead, BinWrite, Debug, Clone)]
pub struct DnsQuestion {
    pub label: DnsLabel,
    pub kind: QuestionType,
    pub class: QuestionClass,
}

#[derive(BinWrite, BinRead, Debug, Clone)]
pub enum DnsResourceRecordData {
    #[brw(magic = 4u16)]
    A { ip: [u8; 4] },
}

#[derive(BinWrite, BinRead, Debug, Clone)]
pub struct DnsResourceRecord {
    pub name: DnsLabel,
    pub kind: QuestionType,
    pub class: QuestionClass,
    pub ttl: u32,
    pub data: DnsResourceRecordData,
}

#[derive(BinRead, BinWrite, Debug, Clone, Default)]
pub struct DnsMessage {
    pub header: DnsHeader,
    #[br(count = header.question_count as usize)]
    pub questions: Vec<DnsQuestion>,
    #[br(count = header.answer_count as usize)]
    pub resource_records: Vec<DnsResourceRecord>,
}
