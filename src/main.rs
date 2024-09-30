// ```
// [dependencies]
// chrono = "0.4.38"
// pcap = "2.2.0"
// pnet = "0.35.0"
// ```

// NOTE: run with:
// cargo run --release -- --vec <path/to.cpap>
// cargo run --release -- --heap <path/to.cpap>
// hyperfine --warmup 3 'cargo run --release -- --vec <path/to.cpap>' 'cargo run --release -- --heap <path/to.cpap>'
//
// cargo run --release -- --heap <path/to.cpap> ran
//   1.07 ± 0.01 times faster than cargo run --release -- --vec <path/to.cpap>

use chrono::{DateTime, FixedOffset, TimeDelta, Utc};
use pcap::{Capture, Offline};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::UdpPacket,
    Packet,
};
use std::{collections::BinaryHeap, fmt::Debug};

/// The maximum delay between accept and packet times
const MAX_DELAY: TimeDelta = TimeDelta::seconds(3);

/// A convenient char array for issue codes.
#[derive(Copy, Clone, Debug)]
pub struct IssueCode([char; 12]);

impl TryFrom<&str> for IssueCode {
    type Error = &'static str;

    fn try_from(str: &str) -> Result<Self, Self::Error> {
        if str.len() != 12 {
            return Err("Must be 12 characters");
        }

        let mut chars = str.chars();

        Ok(Self(std::array::from_fn(|_| chars.next().unwrap())))
    }
}

/// A wrapper of `QuotePacket` to use `BinaryHeap` as a min-heap.
#[derive(Copy, Clone, Debug)]
pub struct OrdQuotePacket(QuotePacket);

impl PartialEq for OrdQuotePacket {
    fn eq(&self, other: &Self) -> bool {
        self.0.accept_time == other.0.accept_time
    }
}

impl Eq for OrdQuotePacket {}

impl PartialOrd for OrdQuotePacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrdQuotePacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.accept_time.cmp(&other.0.accept_time).reverse()
    }
}

/// Best bids/asks prices/quantities of a quote.
#[derive(Copy, Clone, Debug)]
pub struct QuotePacket {
    packet_time: DateTime<Utc>,
    accept_time: DateTime<Utc>,
    issue_code: IssueCode,

    bid_price_1: u32,
    bid_price_2: u32,
    bid_price_3: u32,
    bid_price_4: u32,
    bid_price_5: u32,

    ask_price_1: u32,
    ask_price_2: u32,
    ask_price_3: u32,
    ask_price_4: u32,
    ask_price_5: u32,

    bid_quantity_1: u32,
    bid_quantity_2: u32,
    bid_quantity_3: u32,
    bid_quantity_4: u32,
    bid_quantity_5: u32,

    ask_quantity_1: u32,
    ask_quantity_2: u32,
    ask_quantity_3: u32,
    ask_quantity_4: u32,
    ask_quantity_5: u32,
}

impl QuotePacket {
    pub const DATA_INFO_MARKET: &'static [u8; 5] = b"B6034";

    // NOTE: we could use `thiserror` here for finer error handling depending on real scenario
    pub const DATE_ERROR: &'static str = "Invalid date";
    pub const PARSE_INT_ERROR: &'static str = "Cannot parse number";
    pub const UTF8_ERROR: &'static str = "Invalid UTF-8";

    /// Returns the quote from a `packet`, if any.
    pub fn try_from_packet(packet: pcap::Packet) -> Option<Result<Self, &'static str>> {
        let packet_time = DateTime::from_timestamp_micros(
            packet.header.ts.tv_sec * 1_000_000 + i64::from(packet.header.ts.tv_usec),
        );

        EthernetPacket::new(packet.data)
            .as_ref()
            .and_then(|ethernet_packet| match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => Ipv4Packet::new(ethernet_packet.payload()),
                _ => None,
            })
            .filter(|ipv4_packet| {
                ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp
            })
            .as_ref()
            .and_then(|ipv4_packet| UdpPacket::new(ipv4_packet.payload()))
            .as_ref()
            .map(|udp_packet| udp_packet.payload())
            .filter(|udp_payload| &udp_payload[..5] == Self::DATA_INFO_MARKET)
            .map(|udp_payload| {
                Self::try_from_udp_payload(packet_time.ok_or(Self::DATE_ERROR)?, udp_payload)
            })
    }

    /// Returns the quote from a `udp_payload`.
    pub fn try_from_udp_payload(
        packet_time: DateTime<Utc>,
        udp_payload: &[u8],
    ) -> Result<Self, &'static str> {
        debug_assert!(&udp_payload[..5] == Self::DATA_INFO_MARKET);
        debug_assert!(udp_payload.last() == Some(&0xFF));

        // NOTE: there are ways to make this code a little faster if we allow unsafe
        let from_utf8 = |bytes| std::str::from_utf8(bytes).map_err(|_| Self::UTF8_ERROR);
        let parse_u32 = |str| u32::from_str_radix(str, 10).map_err(|_| Self::PARSE_INT_ERROR);
        let parse = |start, len| parse_u32(from_utf8(&udp_payload[start..start + len])?);
        let parse_price = |start| parse(start, 5);
        let parse_quantity = |start| parse(start, 7);

        let issue_code = from_utf8(&udp_payload[5..17])?.try_into()?;
        let bid_price_1 = parse_price(29)?;
        let bid_quantity_1 = parse_quantity(34)?;
        let bid_price_2 = parse_price(41)?;
        let bid_quantity_2 = parse_quantity(46)?;
        let bid_price_3 = parse_price(53)?;
        let bid_quantity_3 = parse_quantity(58)?;
        let bid_price_4 = parse_price(65)?;
        let bid_quantity_4 = parse_quantity(70)?;
        let bid_price_5 = parse_price(77)?;
        let bid_quantity_5 = parse_quantity(82)?;
        let ask_price_1 = parse_price(96)?;
        let ask_quantity_1 = parse_quantity(101)?;
        let ask_price_2 = parse_price(108)?;
        let ask_quantity_2 = parse_quantity(113)?;
        let ask_price_3 = parse_price(120)?;
        let ask_quantity_3 = parse_quantity(125)?;
        let ask_price_4 = parse_price(132)?;
        let ask_quantity_4 = parse_quantity(137)?;
        let ask_price_5 = parse_price(144)?;
        let ask_quantity_5 = parse_quantity(149)?;

        let accept_time = {
            let korea = FixedOffset::east_opt(9 * 60 * 60).ok_or(Self::DATE_ERROR)?;
            let accept_time = from_utf8(&udp_payload[206..214])?;
            let hours = parse_u32(&accept_time[0..2])?;
            let minutes = parse_u32(&accept_time[2..4])?;
            let seconds = parse_u32(&accept_time[4..6])?;
            let centis = parse_u32(&accept_time[6..8])?;

            // NOTE: for simplicity's sake, we assume it's not 3s around midnight (korea time)
            packet_time
                .date_naive()
                .and_hms_milli_opt(hours, minutes, seconds, centis * 10)
                .ok_or(Self::DATE_ERROR)?
                .and_local_timezone(korea)
                .single()
                .ok_or(Self::DATE_ERROR)?
                .with_timezone(&Utc)
        };

        debug_assert!(accept_time < packet_time);

        Ok(QuotePacket {
            packet_time,
            accept_time,
            issue_code,
            bid_price_1,
            bid_price_2,
            bid_price_3,
            bid_price_4,
            bid_price_5,
            ask_price_1,
            ask_price_2,
            ask_price_3,
            ask_price_4,
            ask_price_5,
            bid_quantity_1,
            bid_quantity_2,
            bid_quantity_3,
            bid_quantity_4,
            bid_quantity_5,
            ask_quantity_1,
            ask_quantity_2,
            ask_quantity_3,
            ask_quantity_4,
            ask_quantity_5,
        })
    }
}

impl std::fmt::Display for QuotePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} ", self.packet_time, self.accept_time)?;

        for char in self.issue_code.0 {
            write!(f, "{char}")?;
        }

        for (quantity, price) in [
            (self.bid_quantity_5, self.bid_price_5),
            (self.bid_quantity_4, self.bid_price_4),
            (self.bid_quantity_3, self.bid_price_3),
            (self.bid_quantity_2, self.bid_price_2),
            (self.bid_quantity_1, self.bid_price_1),
            (self.ask_quantity_1, self.ask_price_1),
            (self.ask_quantity_2, self.ask_price_2),
            (self.ask_quantity_3, self.ask_price_3),
            (self.ask_quantity_4, self.ask_price_4),
            (self.ask_quantity_5, self.ask_price_5),
        ] {
            write!(f, " {quantity:>6}@{price:<6}")?;
        }

        Ok(())
    }
}

fn main() {
    let mut path = None;
    let mut is_vec = false;
    let mut is_heap = false;

    for arg in std::env::args() {
        match arg.as_str() {
            "--vec" => is_vec = true,
            "--heap" => is_heap = true,
            _ => path = Some(arg),
        }
    }

    // NOTE: it seems like `libpcap` does not buffer the full file into memory!
    // Otherwise, we'd have to dig into pcap specs and use a cursor to get relevant udp payloads
    let capture = Capture::from_file(path.expect("Missing `-r <path/to/capture.pcap>`")).unwrap();

    match (is_vec, is_heap) {
        (true, false) => with_vec(capture),
        (false, true) => with_heap(capture),
        _ => panic!("--vec XOR --heap"),
    }
}

fn with_vec(mut capture: Capture<Offline>) {
    let mut window = Vec::<QuotePacket>::with_capacity(2048);

    while let Ok(packet) = capture.next_packet() {
        if let Some(Ok(quote_packet)) = QuotePacket::try_from_packet(packet) {
            // Flush buffered quotes older than the current one, taking MAX_DELAY into account
            for quote_packet in window.drain(
                ..window.partition_point(|probe| {
                    probe.accept_time + MAX_DELAY < quote_packet.accept_time
                }),
            ) {
                println!("{quote_packet}");
            }

            // Insert the current quote in the window at its sorted position
            window.insert(
                window.partition_point(|probe| probe.accept_time <= quote_packet.accept_time),
                quote_packet,
            );
        }
    }

    // Flush the remaining quotes
    for quote_packet in &window {
        println!("{quote_packet}");
    }
}

fn with_heap(mut capture: Capture<Offline>) {
    let mut window = BinaryHeap::<OrdQuotePacket>::with_capacity(2048);

    while let Ok(packet) = capture.next_packet() {
        if let Some(Ok(quote_packet)) = QuotePacket::try_from_packet(packet) {
            // Flush buffered quotes older than the current one, taking MAX_DELAY into account
            loop {
                if let Some(quote_packet) = window
                    .peek()
                    .filter(|peek| peek.0.accept_time + MAX_DELAY < quote_packet.accept_time)
                {
                    println!("{}", quote_packet.0);
                    window.pop().unwrap();
                } else {
                    break;
                }
            }

            // Insert the current quote in the window
            window.push(OrdQuotePacket(quote_packet));
        }
    }

    // Flush the remaining quotes
    while let Some(quote_packet) = window.pop() {
        println!("{}", quote_packet.0);
    }
}
