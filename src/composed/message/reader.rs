mod compressed;
mod limited;
mod literal;
mod packet_body;
mod signed_many;
mod sym_encrypted;
mod sym_encrypted_protected;

pub use self::{
    compressed::CompressedDataReader,
    limited::LimitedReader,
    literal::LiteralDataReader,
    packet_body::PacketBodyReader,
    signed_many::{FullSignaturePacket, SignatureManyReader, SignaturePacket},
    sym_encrypted::SymEncryptedDataReader,
    sym_encrypted_protected::SymEncryptedProtectedDataReader,
};

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read};

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use testresult::TestResult;

    use crate::{
        composed::{Message, MessageBuilder},
        packet::DataMode,
        types::CompressionAlgorithm,
        util::test::{check_strings, random_string, ChaosReader},
    };

    #[test]
    fn test_read_literal_data_no_compression() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..1024 * 10).step_by(100) {
            for is_partial in [true, false] {
                println!("--- size: {file_size}, is_partial: {is_partial}");

                let buf = random_string(&mut rng, file_size);
                let message = if is_partial {
                    let mut builder = MessageBuilder::from_reader("test.txt", buf.as_bytes());
                    builder.partial_chunk_size(512)?;
                    builder.to_vec(&mut rng)?
                } else {
                    MessageBuilder::from_bytes("test.txt", buf.clone()).to_vec(&mut rng)?
                };

                let reader = ChaosReader::new(rng.clone(), message.clone());
                let mut reader = BufReader::new(reader);
                let mut msg = Message::from_bytes(&mut reader).unwrap();

                let mut out = String::new();
                msg.read_to_string(&mut out)?;
                check_strings(out, buf);

                let header = msg.literal_data_header().unwrap();
                assert_eq!(header.file_name(), &b""[..]);
                assert_eq!(header.mode(), DataMode::Binary);
            }
        }
        Ok(())
    }

    #[test]
    fn test_read_literal_data_compression_zip() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..1024 * 10).step_by(100) {
            for is_partial in [true, false] {
                for is_armor in [true, false] {
                    println!(
                        "--- size: {file_size}, is_partial: {is_partial}, is_armor: {is_armor}"
                    );
                    let buf = random_string(&mut rng, file_size);

                    if is_armor {
                        let message = if is_partial {
                            let mut builder =
                                MessageBuilder::from_reader("test.txt", buf.as_bytes());
                            builder
                                .compression(CompressionAlgorithm::ZIP)
                                .partial_chunk_size(512)?;
                            builder.to_armored_string(&mut rng, Default::default())?
                        } else {
                            let mut builder = MessageBuilder::from_bytes("test.txt", buf.clone());
                            builder.compression(CompressionAlgorithm::ZIP);
                            builder.to_armored_string(&mut rng, Default::default())?
                        };
                        let reader = ChaosReader::new(rng.clone(), message.clone());
                        let mut reader = BufReader::new(reader);
                        let (message, _) = Message::from_armor(&mut reader)?;

                        let mut decompressed_message = message.decompress()?;
                        let mut out = String::new();
                        decompressed_message.read_to_string(&mut out)?;

                        check_strings(out, buf);

                        let header = decompressed_message.literal_data_header().unwrap();
                        assert_eq!(header.file_name(), &b""[..]);
                        assert_eq!(header.mode(), DataMode::Binary);
                    } else {
                        let mut builder = MessageBuilder::from_bytes("test.txt", buf.clone());
                        builder.compression(CompressionAlgorithm::ZIP);
                        if is_partial {
                            builder.partial_chunk_size(512)?;
                        }
                        let message = builder.to_vec(&mut rng)?;

                        let reader = ChaosReader::new(rng.clone(), message.clone());
                        let mut reader = BufReader::new(reader);
                        let message = Message::from_bytes(&mut reader)?;

                        let mut decompressed_message = message.decompress()?;
                        let mut out = String::new();
                        decompressed_message.read_to_string(&mut out)?;

                        check_strings(out, buf);

                        let header = decompressed_message.literal_data_header().unwrap();
                        assert_eq!(header.file_name(), &b""[..]);
                        assert_eq!(header.mode(), DataMode::Binary);
                    }
                }
            }
        }
        Ok(())
    }
}
