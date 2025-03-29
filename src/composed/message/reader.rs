use crate::util::fill_buffer;

mod compressed;
mod limited;
mod literal;
mod packet_body;
mod signed;
mod signed_one_pass;
mod sym_encrypted;
mod sym_encrypted_protected;

pub use self::compressed::CompressedDataReader;
pub use self::limited::LimitedReader;
pub use self::literal::LiteralDataReader;
pub use self::packet_body::PacketBodyReader;
pub use self::signed::SignatureBodyReader;
pub use self::signed_one_pass::SignatureOnePassReader;
pub use self::sym_encrypted::SymEncryptedDataReader;
pub use self::sym_encrypted_protected::SymEncryptedProtectedDataReader;

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read};

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use testresult::TestResult;

    use crate::packet::DataMode;
    use crate::types::CompressionAlgorithm;
    use crate::util::test::{check_strings, random_string, ChaosReader};
    use crate::{Message, MessageBuilder};

    #[test]
    fn test_read_literal_data_no_compression() -> TestResult {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for file_size in (1..1024 * 10).step_by(100) {
            for is_partial in [true, false] {
                println!("--- size: {file_size}, is_partial: {is_partial}");

                let buf = random_string(&mut rng, file_size);
                let message = if is_partial {
                    MessageBuilder::from_reader("test.txt", buf.as_bytes())
                        .partial_chunk_size(512)?
                        .to_vec(&mut rng)?
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
                            MessageBuilder::from_reader("test.txt", buf.as_bytes())
                                .compression(CompressionAlgorithm::ZIP)
                                .partial_chunk_size(512)?
                                .to_armored_string(&mut rng, Default::default())?
                        } else {
                            MessageBuilder::from_bytes("test.txt", buf.clone())
                                .compression(CompressionAlgorithm::ZIP)
                                .to_armored_string(&mut rng, Default::default())?
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
                        let message = if is_partial {
                            MessageBuilder::from_reader("test.txt", buf.as_bytes())
                                .compression(CompressionAlgorithm::ZIP)
                                .partial_chunk_size(512)?
                                .to_vec(&mut rng)?
                        } else {
                            MessageBuilder::from_bytes("test.txt", buf.clone())
                                .compression(CompressionAlgorithm::ZIP)
                                .to_vec(&mut rng)?
                        };
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
