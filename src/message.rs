#![allow(dead_code)]

use binrw::BinRead;
use modular_bitfield::prelude::*;

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
enum QueryResponseIndicator {
    Query,
    Response,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
enum AuthoritativeAnswer {
    Other,
    Owns,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
enum Truncation {
    No,
    LargerThan512,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
enum RecursionDesired {
    NonRecursive,
    Recursive,
}

#[derive(BitfieldSpecifier, Debug)]
#[bits = 1]
enum RecursionAvailable {
    NotAvailable,
    Available,
}

#[bitfield]
#[derive(BinRead, Debug)]
#[br(map = Self::from_bytes)]
pub struct DnsHeader {
    /// Packet Identifier (ID)A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,
    /// Query/Response Indicator (QR). 1 for a reply packet, 0 for a question packet.
    qr: QueryResponseIndicator,
    /// Operation Code (OPCODE)	Specifies the kind of query in a message.
    opcode: B4,
    /// Authoritative Answer (AA) 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    authoritative: AuthoritativeAnswer,
    /// Truncation (TC) 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    truncation: Truncation,
    /// Recursion Desired (RD) Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    recursion_desired: RecursionDesired,
    /// Recursion Available (RA) Server sets this to 1 to indicate that recursion is available.
    recursion_available: RecursionAvailable,
    /// Reserved (Z) Used by DNSSEC queries. At inception, it was reserved for future use.
    #[skip]
    __: B3,
    /// Response Code (RCODE) Response code indicating the status of the response.
    response: B4,
    /// Question Count (QDCOUNT) Number of questions in the Question section.
    question_count: u16,
    /// Answer Record Count (ANCOUNT) Number of records in the Answer section.
    answer_count: u16,
    /// Authority Record Count (NSCOUNT)	16 bits	Number of records in the Authority section.
    nscount: u16,
    /// Additional Record Count (ARCOUNT)	16 bits	Number of records in the Additional section.
    arcount: u16,
}
