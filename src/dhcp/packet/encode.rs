use std::io::{Cursor, Write};

use byteorder::{NetworkEndian, WriteBytesExt};

use super::Packet;

impl Packet {
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.server_name.as_deref().map(|x| x.len()).unwrap_or(0) < 64);
        assert!(self.boot_file_name.as_deref().map(|x| x.len()).unwrap_or(0) < 128);

        let mut cursor = {
            let mut buf = Vec::<u8>::new();
            buf.resize(236, 0);
            Cursor::new(buf)
        };
        cursor.write_u8(self.bootp_message_type.into()).unwrap();
        cursor.write_u8(self.htype).unwrap();
        cursor.write_u8(self.hlen).unwrap();
        cursor.write_u8(self.hops).unwrap();
        cursor.write_u32::<NetworkEndian>(self.xid).unwrap();
        cursor.write_u16::<NetworkEndian>(self.secs).unwrap();
        cursor.write_u16::<NetworkEndian>(self.flags).unwrap();
        cursor.write_all(&self.ciaddr.octets()[..]).unwrap();
        cursor.write_all(&self.yiaddr.octets()[..]).unwrap();
        cursor.write_all(&self.siaddr.octets()[..]).unwrap();
        cursor.write_all(&self.giaddr.octets()[..]).unwrap();
        cursor.write_all(&self.mac.get_raw()[..]).unwrap();

        if let Some(server_name) = self.server_name.as_deref() {
            cursor.write_all(server_name.as_bytes()).unwrap();
            cursor.set_position(cursor.position() + 64 - server_name.len() as u64);
        } else {
            cursor.set_position(cursor.position() + 64);
        }

        if let Some(boot_file_name) = self.boot_file_name.as_deref() {
            cursor.write_all(boot_file_name.as_bytes()).unwrap();
            cursor.set_position(cursor.position() + 128 - boot_file_name.len() as u64);
        } else {
            cursor.set_position(cursor.position() + 128);
        }

        assert_eq!(cursor.position(), 236);

        if !self.options.is_empty() {
            cursor.write_all(&[99, 130, 83, 99]).unwrap();

            for (&tag, option) in self.options.iter() {
                assert_eq!(tag, option.tag());

                cursor.write_u8(tag).unwrap();
                cursor.write_u8(option.len()).unwrap();
                option.encode(&mut cursor).unwrap();
            }

            cursor.write_u8(0xff).unwrap();
        }

        cursor.into_inner()
    }
}
