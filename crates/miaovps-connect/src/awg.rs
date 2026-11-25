//! Framing shared by validation, data plane, and every handshake retry.
use awgtun::amnezia::{Amnezia2Config, HeaderConfig, HeaderRange, JunkConfig, PaddingConfig};
use awgtun::noise::{Packet, Tunn, TunnResult};

use crate::ConnectError;

#[derive(Clone, Copy, Default)]
pub struct Framing {
    headers: HeaderConfig,
    padding: PaddingConfig,
    junk: JunkConfig,
}

impl Framing {
    // shortcut: accept the MiaoVPS H/S/J profile subset; add other AWG options when provisioning supports them.
    pub fn amnezia(
        headers: [u32; 4],
        padding: [u16; 2],
        junk: [u16; 3],
    ) -> Result<Self, ConnectError> {
        let invalid = |e: awgtun::amnezia::ConfigError| ConnectError::WireGuardError(e.to_string());
        if headers.contains(&0)
            || padding.iter().any(|n| *n > 108)
            || junk[0] > 16
            || junk[2] > 1400
            || (junk[0] > 0 && (junk[1] == 0 || junk[1] >= junk[2]))
        {
            return Err(ConnectError::WireGuardError(
                "AWG framing exceeds MiaoVPS limits".into(),
            ));
        }
        let [h1, h2, h3, h4] = headers.map(HeaderRange::single);
        Ok(Self {
            headers: HeaderConfig::new(h1, h2, h3, h4).map_err(invalid)?,
            padding: PaddingConfig::new(padding[0], padding[1], 0, 0).map_err(invalid)?,
            junk: JunkConfig::new(junk[0], junk[1], junk[2]).map_err(invalid)?,
        })
    }

    pub(crate) fn tunnel(
        self,
        private: [u8; 32],
        public: [u8; 32],
        keepalive: Option<u16>,
    ) -> Tunn {
        let mut config = Amnezia2Config::default();
        config.headers = self.headers;
        config.paddings = self.padding;
        config.junk = self.junk;
        Tunn::new_with_amnezia(
            private.into(),
            public.into(),
            None,
            keepalive,
            0,
            None,
            config,
        )
        .expect("validated framing")
    }

    pub(crate) fn packet_type(self, packet: &[u8]) -> u8 {
        for (pad, kind) in [(self.padding.s1, 1), (self.padding.s2, 2), (0, 4)] {
            let Some(packet) = packet.get(usize::from(pad)..) else {
                continue;
            };
            let parsed = Tunn::parse_incoming_packet_config(packet, &self.headers);
            if matches!(
                (kind, parsed),
                (1, Ok(Packet::HandshakeInit(_)))
                    | (2, Ok(Packet::HandshakeResponse(_)))
                    | (4, Ok(Packet::PacketData(_)))
            ) {
                return kind;
            }
        }
        0
    }
}

/// Drain junk eagerly under the same tunnel lock, so retries and concurrent sends
/// never pick up another handshake's prefix. The caller sends outside that lock.
pub(crate) fn outgoing(tunn: &mut Tunn, result: TunnResult<'_>) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while let Some(packet) = tunn.poll_outgoing_packet() {
        packets.push(packet);
    }
    if let TunnResult::WriteToNetwork(packet) = result {
        packets.push(packet.to_vec());
    }
    packets
}
