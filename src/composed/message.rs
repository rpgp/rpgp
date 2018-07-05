/// A PGP message
#[derive(Debug)]
pub struct Message {}

#[cfg(test)]
mod tests {
    use super::*;
    use glob::glob;
    use serde_json;
    use std::fs::File;

    use composed::key::PrivateKey;
    use composed::Deserializable;

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct Testcase {
        typ: Option<String>,
        decrypt_key: String,
        passphrase: String,
        verify_key: Option<String>,
        filename: Option<String>,
        timestamp: Option<u64>,
        textcontent: Option<String>,
    }

    #[test]
    fn test_parse_pgp_messages() {
        let base_path = "./tests/opengpg-interop/testcases/messages";
        for entry in glob("./tests/opengpg-interop/testcases/messages/*.json").unwrap() {
            let entry = entry.unwrap();
            let mut file = File::open(&entry).unwrap();

            let details: Testcase = serde_json::from_reader(&mut file).unwrap();
            println!("{:?}: {:?}", entry, details);

            let mut key_file =
                File::open(format!("{}/{}", base_path, details.decrypt_key)).unwrap();
            let key = PrivateKey::from_armor_single(&mut key_file).unwrap();

            let file_name = entry.to_str().unwrap().replace(".json", ".asc");
            let mut cipher_file = File::open(file_name).unwrap();

            // let message = Message::from_armor_single(&mut cipher_file).unwrap();

            // key.primary_key
            //     .unlock(
            //         || "",
            //         |unlocked_key| {
            //             let decrypted = message.decrypt(|| details.passphrase, unlocked_key);
            //             assert_eq!(
            //                 decrypted,
            //                 details.textcontent.unwrap_or_else(|| "".to_string())
            //             );
            //             Ok(())
            //         },
            //     )
            //     .unwrap();
        }
    }
}
