use bitflags::bitflags;
use rand::random;
use std::fmt::{Debug, Display};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::string::FromUtf8Error;
use thiserror::Error;

fn read_u16(bytes: &mut &[u8]) -> Result<u16, DNSParseError> {
    let val = u16::from_be_bytes(
        bytes
            .get(0..2)
            .ok_or(DNSParseError::InvalidData)?
            .try_into()
            .map_err(|_| DNSParseError::InvalidData)?,
    );
    *bytes = &bytes[2..];
    Ok(val)
}

fn read_u32(bytes: &mut &[u8]) -> Result<u32, DNSParseError> {
    let val = u32::from_be_bytes(
        bytes
            .get(0..4)
            .ok_or(DNSParseError::InvalidData)?
            .try_into()
            .map_err(|_| DNSParseError::InvalidData)?,
    );
    *bytes = &bytes[4..];
    Ok(val)
}

bitflags! {
    #[derive(Debug, Copy, Clone)]
    pub struct QueryFlags: u16 {
        // Indicates if the message is a query (0) or a reply (1)
        const qr     = 0b1000000000000000;
        // The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2)
        const opcode = 0b0111100000000000;
        // Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname
        const aa     = 0b0000010000000000;
        // TrunCation, indicates that this message was truncated due to excessive length
        const tc     = 0b0000001000000000;
        // Recursion Desired, indicates if the client means a recursive query
        const rd     = 0b0000000100000000;
        // Recursion Available, in a response, indicates if the replying DNS server supports recursion
        const ra     = 0b0000000010000000;
        // Zero, reserved for future use
        const z      = 0b0000000001110000;
        // Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.
        const rcode  = 0b0000000000001111;
    }
}

impl Default for QueryFlags {
    // This will make a flagset for standard queries
    fn default() -> Self {
        QueryFlags::from_bits(0x0100).unwrap()
    }
}

impl QueryFlags {
    pub fn successful(&self) -> bool {
        (*self & QueryFlags::rcode).is_empty() && self.contains(QueryFlags::qr)
    }
}

#[derive(Debug)]
pub struct Query {
    pub transaction_id: u16,
    pub flags: QueryFlags,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authority_rrs: u16,
    pub num_additional_rr: u16,
    pub resource_answers: Vec<QueryAnswer>,
    pub resource_queries: Vec<QueryQuestion>,
    pub resource_authorities: Vec<AuthoritativeNameserverAnswer>,
}

impl Query {
    pub fn for_name(name: &str, record_type: RecordType) -> Self {
        const CLASS_INET: u16 = 1;

        Query {
            transaction_id: random(),
            flags: QueryFlags::default(),
            num_questions: 1,
            num_answers: 0,
            num_authority_rrs: 0,
            num_additional_rr: 0,
            resource_answers: vec![],
            resource_queries: vec![QueryQuestion {
                name: name.to_string(),
                record_type,
                class_code: CLASS_INET,
            }],
            resource_authorities: vec![],
        }
    }
    pub fn as_bytes(&self) -> Result<Vec<u8>, DNSParseError> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.transaction_id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.bits().to_be_bytes());
        bytes.extend_from_slice(&self.num_questions.to_be_bytes());
        bytes.extend_from_slice(&self.num_answers.to_be_bytes());
        bytes.extend_from_slice(&self.num_authority_rrs.to_be_bytes());
        bytes.extend_from_slice(&self.num_additional_rr.to_be_bytes());

        assert_eq!(bytes.len(), 12);

        for rec in &self.resource_queries {
            bytes.append(&mut rec.as_bytes()?)
        }

        Ok(bytes)
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Query, DNSParseError> {
        let all_bytes = bytes;

        let transaction = read_u16(&mut bytes).map_err(|_| DNSParseError::InvalidQuery)?;
        let flags = read_u16(&mut bytes).map_err(|_| DNSParseError::InvalidQuery)?;
        let num_questions = read_u16(&mut bytes).map_err(|_| DNSParseError::InvalidQuery)?;
        let answer_rrs = read_u16(&mut bytes).map_err(|_| DNSParseError::InvalidQuery)?;
        let authority_rrs = read_u16(&mut bytes).map_err(|_| DNSParseError::InvalidQuery)?;
        let additional_rrs = read_u16(&mut bytes).map_err(|_| DNSParseError::InvalidQuery)?;

        let mut questions = Vec::new();
        for _ in 0..num_questions {
            let question = QueryQuestion::from_bytes(&mut bytes)?;
            questions.push(question);
        }

        let mut answers = Vec::new();
        for _ in 0..answer_rrs {
            let answer = QueryAnswer::from_bytes(all_bytes, &mut bytes)?;
            answers.push(answer);
        }

        let mut authoritys = Vec::new();
        for _ in 0..authority_rrs {
            let authority = AuthoritativeNameserverAnswer::from_bytes(all_bytes, &mut bytes)?;
            authoritys.push(authority);
        }

        Ok(Query {
            transaction_id: transaction,
            flags: QueryFlags::from_bits_retain(flags),
            num_questions,
            num_answers: answer_rrs,
            num_authority_rrs: authority_rrs,
            num_additional_rr: additional_rrs,
            resource_answers: answers,
            resource_queries: questions,
            resource_authorities: authoritys,
        })
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    SRV = 33,
    NS = 2,
    MX = 15,
    TXT = 16,
}

impl TryFrom<u16> for RecordType {
    type Error = DNSParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(RecordType::A),
            28 => Ok(RecordType::AAAA),
            5 => Ok(RecordType::CNAME),
            33 => Ok(RecordType::SRV),
            2 => Ok(RecordType::NS),
            15 => Ok(RecordType::MX),
            16 => Ok(RecordType::TXT),
            _ => return Err(DNSParseError::InvalidType),
        }
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::NS => write!(f, "NS"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
        }
    }
}

impl RecordType {
    pub fn id(&self) -> u16 {
        *self as u16
    }
}

fn encode_name(name: &str) -> Result<Vec<u8>, DNSParseError> {
    let mut bytes = vec![];

    for domain in name.split_terminator('.') {
        let len = domain.len();
        if len > u8::MAX as usize {
            return Err(DNSParseError::NameTooLong);
        }
        let len = len as u8;

        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(domain.as_bytes());
    }
    bytes.push(0);

    Ok(bytes)
}

const MAX_COMPRESSION_LAYER: u32 = 5;

fn decode_name_internal(
    all_bytes: &[u8],
    bytes: &mut &[u8],
    compression_layer: u32,
) -> Result<String, DNSParseError> {
    let mut iter = bytes.iter().peekable();
    let mut name = String::new();

    let mut len = *iter.next().ok_or(DNSParseError::InvalidName)?;
    if len == 0 {
        *bytes = &bytes[1..];
        return Ok(".".to_string());
    }

    while iter.peek().is_some() {
        // compressed domain name
        if len == 0xC0 {
            if compression_layer > MAX_COMPRESSION_LAYER {
                return Err(DNSParseError::MultiCompressRecursionPass);
            }
            let offset = *iter.next().ok_or(DNSParseError::InvalidName)? as usize;
            name.push_str(
                &decode_name_internal(
                    all_bytes,
                    &mut all_bytes.get(offset..).ok_or(DNSParseError::InvalidName)?,
                    compression_layer + 1,
                )
                .map_err(|_| DNSParseError::InvalidName)?,
            );
            *bytes = &bytes[2..];
            return Ok(name);
        }

        if len == 0 {
            *bytes = &bytes[1..];
            break;
        }

        let mut domain = Vec::new();
        for _ in 0..len {
            domain.push(*iter.next().ok_or(DNSParseError::InvalidName)?);
        }
        let domain = String::from_utf8(domain)?;
        name.push_str(domain.as_str());

        name.push('.');

        *bytes = &bytes[len as usize + 1..];
        len = *iter.next().ok_or(DNSParseError::InvalidName)?;
    }

    Ok(name)
}

fn decode_name(all_bytes: &[u8], bytes: &mut &[u8]) -> Result<String, DNSParseError> {
    decode_name_internal(all_bytes, bytes, 0)
}

#[test]
fn test_en_decode() {
    let encoded = encode_name("meow.com").unwrap();
    assert_eq!(encoded, vec![4, 109, 101, 111, 119, 3, 99, 111, 109, 0]);

    let encoded = encode_name("meow.com.").unwrap();
    assert_eq!(encoded, vec![4, 109, 101, 111, 119, 3, 99, 111, 109, 0]);

    let mew = "meow.com.";
    let encoded = encode_name(mew).unwrap();
    let decoded = decode_name(&encoded, &mut encoded.as_slice()).unwrap();
    assert_eq!(decoded, mew);
}

#[derive(Debug)]
pub struct QueryQuestion {
    name: String,
    record_type: RecordType,
    class_code: u16,
}

impl QueryQuestion {
    pub fn new(name: &str, record_type: RecordType) -> QueryQuestion {
        QueryQuestion {
            name: name.to_string(),
            record_type,
            class_code: 1,
        }
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, DNSParseError> {
        let mut bytes = vec![];

        bytes.append(&mut encode_name(self.name.as_str())?);
        bytes.extend_from_slice(&self.record_type.id().to_be_bytes());
        bytes.extend_from_slice(&self.class_code.to_be_bytes());

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &mut &[u8]) -> Result<QueryQuestion, DNSParseError> {
        let name = decode_name(*bytes, bytes).map_err(|_| DNSParseError::InvalidName)?;

        let record_type: RecordType = read_u16(bytes)
            .map_err(|_| DNSParseError::InvalidType)?
            .try_into()?;

        let class = read_u16(bytes).map_err(|_| DNSParseError::InvalidClass)?;

        Ok(QueryQuestion {
            name,
            record_type,
            class_code: class,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct QueryAnswer {
    name: String,
    ty: u16,
    class: u16,
    time_to_live: u32,
    data: Vec<u8>,
}

impl QueryAnswer {
    pub fn from_bytes(all_bytes: &[u8], bytes: &mut &[u8]) -> Result<Self, DNSParseError> {
        let name = decode_name(all_bytes, bytes)?;

        let ty = read_u16(bytes).map_err(|_| DNSParseError::InvalidType)?;
        let class = read_u16(bytes).map_err(|_| DNSParseError::InvalidClass)?;
        let time_to_live = read_u32(bytes).map_err(|_| DNSParseError::InvalidTTL)?;
        let data_length = read_u16(bytes).map_err(|_| DNSParseError::InvalidData)?;
        let data = bytes
            .get(0..data_length as usize)
            .ok_or(DNSParseError::InvalidData)?
            .to_vec();
        *bytes = &bytes[data_length as usize..];

        Ok(QueryAnswer {
            name,
            ty,
            class,
            time_to_live,
            data,
        })
    }

    pub fn entry_type(&self) -> Option<RecordType> {
        RecordType::try_from(self.ty).ok()
    }

    pub fn data_as_ipv6(&self) -> Result<Ipv6Addr, DNSParseError> {
        const IPV6_OCTETS: usize = 16;

        if self.data.len() != IPV6_OCTETS {
            return Err(DNSParseError::InvalidData);
        }

        let ipv6_data: [u8; IPV6_OCTETS] = self.data.as_slice().try_into().unwrap();
        Ok(Ipv6Addr::from(ipv6_data))
    }

    pub fn data_as_ipv4(&self) -> Result<Ipv4Addr, DNSParseError> {
        const IPV4_OCTETS: usize = 4;

        if self.data.len() != IPV4_OCTETS {
            return Err(DNSParseError::InvalidData);
        }

        Ok(Ipv4Addr::new(
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ))
    }

    pub fn data_as_text(&self) -> Result<String, DNSParseError> {
        String::from_utf8(self.data.clone()).map_err(|_| DNSParseError::InvalidData)
    }

    pub fn data_as_text_lossy(&self) -> Result<String, DNSParseError> {
        Ok(String::from_utf8_lossy(self.data.as_slice()).to_string())
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct AuthoritativeNameserverAnswer {
    name: String,
    ty: u16,
    class: u16,
    time_to_live: u32,
    data_length: u16,
    primary_nameserver: String,
    responsible_authority_mailbox: String,
    serial_number: u32,
    refresh_interval: u32,
    retry_interval: u32,
    expire_limit: u32,
    minimum_ttl: u32,
}

impl AuthoritativeNameserverAnswer {
    pub fn from_bytes(
        all_bytes: &[u8],
        bytes: &mut &[u8],
    ) -> Result<AuthoritativeNameserverAnswer, DNSParseError> {
        let name = decode_name(all_bytes, bytes)?;
        let ty = read_u16(bytes)?;
        let class = read_u16(bytes)?;
        let time_to_live = read_u32(bytes)?;
        let data_length = read_u16(bytes)?;
        let primary_nameserver = decode_name(all_bytes, bytes)?;
        let responsible_authority_mailbox = decode_name(all_bytes, bytes)?;
        let serial_number = read_u32(bytes)?;
        let refresh_interval = read_u32(bytes)?;
        let retry_interval = read_u32(bytes)?;
        let expire_limit = read_u32(bytes)?;
        let minimum_ttl = read_u32(bytes)?;

        Ok(AuthoritativeNameserverAnswer {
            name,
            ty,
            class,
            time_to_live,
            data_length,
            primary_nameserver,
            responsible_authority_mailbox,
            serial_number,
            refresh_interval,
            retry_interval,
            expire_limit,
            minimum_ttl,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn primary_ns(&self) -> &str {
        &self.primary_nameserver
    }

    pub fn responsible_mail(&self) -> &str {
        &self.responsible_authority_mailbox
    }
}

#[derive(Debug, Error)]
pub enum DNSParseError {
    #[error("The name used was too long (256 maximum length)")]
    NameTooLong,
    #[error("An invalid name was provided")]
    InvalidName,
    #[error("An invalidly formatted non UTF-8 name was provided")]
    InvalidFormattedName(#[from] FromUtf8Error),
    #[error("The provided answer was invalid")]
    InvalidAnswer,
    #[error("The provided type was invalid")]
    InvalidType,
    #[error("The provided code was invalid")]
    InvalidClass,
    #[error("The provided time to live was invalid")]
    InvalidTTL,
    #[error("The provided data was invalid")]
    InvalidData,
    #[error("An invalid query was provided")]
    InvalidQuery,
    #[error("The parser was trying to follow a compressed dns name after following one already")]
    MultiCompressRecursionPass,
}
