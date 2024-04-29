#![allow(dead_code)]

use binrw::{BinRead, BinWrite};
use modular_bitfield::prelude::*;

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
#[derive(BinRead, BinWrite, Debug, Default)]
#[br(map = Self::from_bytes)]
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
#[derive(BinRead, BinWrite, Debug, Default)]
#[br(map = Self::from_bytes)]
pub struct DnsHeaderFlags2 {
    /// Response Code (RCODE) Response code indicating the status of the response.
    pub response: B4,
    /// Reserved (Z) Used by DNSSEC queries. At inception, it was reserved for future use.
    #[skip]
    __: B3,
    /// Recursion Available (RA) Server sets this to 1 to indicate that recursion is available.
    pub recursion_available: RecursionAvailable,
}

#[derive(BinRead, BinWrite, Debug, Default)]
pub struct DnsHeader {
    /// Packet Identifier (ID)A random ID assigned to query packets. Response packets must reply with the same ID.
    pub id: u16,

    pub flags: DnsHeaderFlags,

    pub flags2: DnsHeaderFlags2,

    /// Question Count (QDCOUNT) Number of questions in the Question section.
    pub question_count: u16,

    /// Answer Record Count (ANCOUNT) Number of records in the Answer section.
    pub answer_count: u16,

    /// Authority Record Count (NSCOUNT)	16 bits	Number of records in the Authority section.
    pub nscount: u16,

    /// Additional Record Count (ARCOUNT)	16 bits	Number of records in the Additional section.
    pub arcount: u16,
}
