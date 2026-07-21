use serde::Serialize;

use crate::query::frida_hook::{
    FridaArgumentKind, FridaArgumentSpec, FridaCaptureDirection, FridaHookRequest, FridaStalkerMode,
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaHookRecipe {
    pub recipe_id: String,
    pub provider: String,
    pub display_name: String,
    pub description: String,
    pub request: FridaHookRequest,
    pub evidence_roles: Vec<String>,
    pub warnings: Vec<String>,
}

fn argument(
    index: u8,
    label: &str,
    kind: FridaArgumentKind,
    direction: FridaCaptureDirection,
    length: Option<u32>,
    length_arg: Option<u8>,
    length_pointer_arg: Option<u8>,
) -> FridaArgumentSpec {
    FridaArgumentSpec {
        index,
        label: Some(label.to_string()),
        kind,
        direction,
        length,
        length_arg,
        length_pointer_arg,
    }
}

fn request(
    module_name: &str,
    symbol: &str,
    arguments: Vec<FridaArgumentSpec>,
    max_bytes: u32,
) -> FridaHookRequest {
    FridaHookRequest {
        module_name: module_name.to_string(),
        symbol: Some(symbol.to_string()),
        offset: None,
        function_name: Some(symbol.to_string()),
        arguments,
        capture_registers: true,
        capture_return: true,
        capture_backtrace: false,
        stalker: FridaStalkerMode::Off,
        stalker_duration_ms: 10_000,
        max_bytes,
    }
}

fn recipe(
    recipe_id: &str,
    provider: &str,
    display_name: &str,
    description: &str,
    request: FridaHookRequest,
    evidence_roles: &[&str],
    warnings: &[&str],
) -> FridaHookRecipe {
    FridaHookRecipe {
        recipe_id: recipe_id.to_string(),
        provider: provider.to_string(),
        display_name: display_name.to_string(),
        description: description.to_string(),
        request,
        evidence_roles: evidence_roles
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        warnings: warnings.iter().map(|value| (*value).to_string()).collect(),
    }
}

fn one_shot_digest_recipe(
    recipe_id: &str,
    provider: &str,
    display_name: &str,
    module_name: &str,
    symbol: &str,
    digest_length: u32,
) -> FridaHookRecipe {
    recipe(
        recipe_id,
        provider,
        display_name,
        "Capture a one-shot digest input and the exact fixed-size digest output.",
        request(
            module_name,
            symbol,
            vec![
                argument(
                    0,
                    "input",
                    FridaArgumentKind::ByteArray,
                    FridaCaptureDirection::Input,
                    None,
                    Some(1),
                    None,
                ),
                argument(
                    1,
                    "inputLength",
                    FridaArgumentKind::Integer,
                    FridaCaptureDirection::Input,
                    None,
                    None,
                    None,
                ),
                argument(
                    2,
                    "digest",
                    FridaArgumentKind::ByteArray,
                    FridaCaptureDirection::Output,
                    Some(digest_length),
                    None,
                    None,
                ),
            ],
            4096,
        ),
        &["input", "digest", "deterministic-recomputation"],
        &["Confirm the exported symbol and ABI match the selected library build."],
    )
}

pub fn list_frida_hook_recipes() -> Vec<FridaHookRecipe> {
    let mut recipes = vec![
        one_shot_digest_recipe(
            "openssl-md5-one-shot",
            "OpenSSL/BoringSSL",
            "MD5 one-shot",
            "libcrypto.so",
            "MD5",
            16,
        ),
        one_shot_digest_recipe(
            "openssl-sha1-one-shot",
            "OpenSSL/BoringSSL",
            "SHA-1 one-shot",
            "libcrypto.so",
            "SHA1",
            20,
        ),
        one_shot_digest_recipe(
            "openssl-sha256-one-shot",
            "OpenSSL/BoringSSL",
            "SHA-256 one-shot",
            "libcrypto.so",
            "SHA256",
            32,
        ),
        one_shot_digest_recipe(
            "openssl-sha384-one-shot",
            "OpenSSL/BoringSSL",
            "SHA-384 one-shot",
            "libcrypto.so",
            "SHA384",
            48,
        ),
        one_shot_digest_recipe(
            "openssl-sha512-one-shot",
            "OpenSSL/BoringSSL",
            "SHA-512 one-shot",
            "libcrypto.so",
            "SHA512",
            64,
        ),
        recipe(
            "openssl-evp-digest-update",
            "OpenSSL/BoringSSL",
            "EVP_DigestUpdate input",
            "Capture streaming digest input bytes and length for one update call.",
            request(
                "libcrypto.so",
                "EVP_DigestUpdate",
                vec![
                    argument(
                        1,
                        "input",
                        FridaArgumentKind::ByteArray,
                        FridaCaptureDirection::Input,
                        None,
                        Some(2),
                        None,
                    ),
                    argument(
                        2,
                        "inputLength",
                        FridaArgumentKind::Integer,
                        FridaCaptureDirection::Input,
                        None,
                        None,
                        None,
                    ),
                ],
                4096,
            ),
            &["input", "streaming-digest"],
            &["A single update call is not the complete digest message; correlate context and final calls manually."],
        ),
        recipe(
            "openssl-evp-digest-final-ex",
            "OpenSSL/BoringSSL",
            "EVP_DigestFinal_ex output",
            "Capture the digest using the u32 length returned through *X2.",
            request(
                "libcrypto.so",
                "EVP_DigestFinal_ex",
                vec![argument(
                    1,
                    "digest",
                    FridaArgumentKind::ByteArray,
                    FridaCaptureDirection::Output,
                    None,
                    None,
                    Some(2),
                )],
                128,
            ),
            &["digest", "streaming-digest"],
            &["Correlate the EVP_MD_CTX pointer with earlier update calls before reconstructing the full message."],
        ),
        recipe(
            "openssl-hmac-materials",
            "OpenSSL/BoringSSL",
            "HMAC key/input/output",
            "Capture HMAC key, message, and the output length returned through *X6.",
            request(
                "libcrypto.so",
                "HMAC",
                vec![
                    argument(
                        1,
                        "key",
                        FridaArgumentKind::ByteArray,
                        FridaCaptureDirection::Input,
                        None,
                        Some(2),
                        None,
                    ),
                    argument(
                        2,
                        "keyLength",
                        FridaArgumentKind::Integer,
                        FridaCaptureDirection::Input,
                        None,
                        None,
                        None,
                    ),
                    argument(
                        3,
                        "input",
                        FridaArgumentKind::ByteArray,
                        FridaCaptureDirection::Input,
                        None,
                        Some(4),
                        None,
                    ),
                    argument(
                        4,
                        "inputLength",
                        FridaArgumentKind::Integer,
                        FridaCaptureDirection::Input,
                        None,
                        None,
                        None,
                    ),
                    argument(
                        5,
                        "mac",
                        FridaArgumentKind::ByteArray,
                        FridaCaptureDirection::Output,
                        None,
                        None,
                        Some(6),
                    ),
                ],
                4096,
            ),
            &["key", "input", "mac"],
            &["The EVP_MD pointer in X0 determines the hash; identify it independently before claiming an HMAC algorithm."],
        ),
        recipe(
            "openssl-pbkdf2-hmac-materials",
            "OpenSSL/BoringSSL",
            "PKCS5_PBKDF2_HMAC materials",
            "Capture password, salt, iteration count, requested output length, and derived key.",
            request(
                "libcrypto.so",
                "PKCS5_PBKDF2_HMAC",
                vec![
                    argument(0, "password", FridaArgumentKind::ByteArray, FridaCaptureDirection::Input, None, Some(1), None),
                    argument(1, "passwordLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                    argument(2, "salt", FridaArgumentKind::ByteArray, FridaCaptureDirection::Input, None, Some(3), None),
                    argument(3, "saltLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                    argument(4, "iterations", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                    argument(6, "derivedKeyLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                    argument(7, "derivedKey", FridaArgumentKind::ByteArray, FridaCaptureDirection::Output, None, Some(6), None),
                ],
                4096,
            ),
            &["password", "salt", "iterations", "derived-key"],
            &[
                "A negative password length means NUL-terminated input and is not represented safely by lengthArg; switch X0 to utf8String for that call shape.",
                "The EVP_MD pointer in X5 determines the PRF and must be identified independently before deterministic PBKDF2 verification.",
            ],
        ),
        recipe(
            "openssl-evp-encrypt-update",
            "OpenSSL/BoringSSL",
            "EVP_EncryptUpdate buffers",
            "Capture plaintext input and the exact ciphertext bytes reported through *X2.",
            request(
                "libcrypto.so",
                "EVP_EncryptUpdate",
                vec![
                    argument(1, "ciphertext", FridaArgumentKind::ByteArray, FridaCaptureDirection::Output, None, None, Some(2)),
                    argument(3, "plaintext", FridaArgumentKind::ByteArray, FridaCaptureDirection::Input, None, Some(4), None),
                    argument(4, "inputLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                ],
                4096,
            ),
            &["plaintext", "ciphertext"],
            &["Key, IV, mode, padding, and prior EVP_CIPHER_CTX state are not exposed by this call alone."],
        ),
        recipe(
            "openssl-evp-decrypt-update",
            "OpenSSL/BoringSSL",
            "EVP_DecryptUpdate buffers",
            "Capture ciphertext input and the exact plaintext bytes reported through *X2.",
            request(
                "libcrypto.so",
                "EVP_DecryptUpdate",
                vec![
                    argument(1, "plaintext", FridaArgumentKind::ByteArray, FridaCaptureDirection::Output, None, None, Some(2)),
                    argument(3, "ciphertext", FridaArgumentKind::ByteArray, FridaCaptureDirection::Input, None, Some(4), None),
                    argument(4, "inputLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                ],
                4096,
            ),
            &["ciphertext", "plaintext"],
            &["Key, IV, mode, padding, and prior EVP_CIPHER_CTX state are not exposed by this call alone."],
        ),
        one_shot_digest_recipe(
            "commoncrypto-cc-md5-one-shot",
            "Apple CommonCrypto",
            "CC_MD5 one-shot",
            "libcommonCrypto.dylib",
            "CC_MD5",
            16,
        ),
        one_shot_digest_recipe(
            "commoncrypto-cc-sha1-one-shot",
            "Apple CommonCrypto",
            "CC_SHA1 one-shot",
            "libcommonCrypto.dylib",
            "CC_SHA1",
            20,
        ),
        one_shot_digest_recipe(
            "commoncrypto-cc-sha256-one-shot",
            "Apple CommonCrypto",
            "CC_SHA256 one-shot",
            "libcommonCrypto.dylib",
            "CC_SHA256",
            32,
        ),
        one_shot_digest_recipe(
            "commoncrypto-cc-sha384-one-shot",
            "Apple CommonCrypto",
            "CC_SHA384 one-shot",
            "libcommonCrypto.dylib",
            "CC_SHA384",
            48,
        ),
        one_shot_digest_recipe(
            "commoncrypto-cc-sha512-one-shot",
            "Apple CommonCrypto",
            "CC_SHA512 one-shot",
            "libcommonCrypto.dylib",
            "CC_SHA512",
            64,
        ),
        recipe(
            "commoncrypto-cccrypt-key-input",
            "Apple CommonCrypto",
            "CCCrypt key/input materials",
            "Capture the key and input bytes available in X0-X7.",
            request(
                "libcommonCrypto.dylib",
                "CCCrypt",
                vec![
                    argument(3, "key", FridaArgumentKind::ByteArray, FridaCaptureDirection::Input, None, Some(4), None),
                    argument(4, "keyLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                    argument(6, "input", FridaArgumentKind::ByteArray, FridaCaptureDirection::Input, None, Some(7), None),
                    argument(7, "inputLength", FridaArgumentKind::Integer, FridaCaptureDirection::Input, None, None, None),
                ],
                4096,
            ),
            &["key", "input"],
            &[
                "CCCrypt output arguments are passed after X7 on ARM64 and are intentionally not guessed by the X0-X7 recipe model.",
                "IV length depends on the selected algorithm; add an explicit verified X5 capture length manually when appropriate.",
            ],
        ),
    ];
    recipes.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.display_name.cmp(&right.display_name))
    });
    recipes
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::query::frida_hook::generate_frida_hook;

    #[test]
    fn recipes_have_unique_ids_and_generate_frida_16_scripts() {
        let recipes = list_frida_hook_recipes();
        assert!(recipes.len() >= 16);
        let mut ids = HashSet::new();
        for recipe in recipes {
            assert!(ids.insert(recipe.recipe_id.clone()));
            let generated = generate_frida_hook(&recipe.request).unwrap();
            assert_eq!(generated.frida_api_version, "16.x");
            assert!(generated.script.contains("Interceptor.attach"));
            assert!(!generated.script.contains("frida.attach"));
        }
    }

    #[test]
    fn recipes_use_exact_output_length_pointers_where_the_abi_provides_them() {
        let recipes = list_frida_hook_recipes();
        for id in [
            "openssl-evp-digest-final-ex",
            "openssl-hmac-materials",
            "openssl-evp-encrypt-update",
            "openssl-evp-decrypt-update",
        ] {
            let recipe = recipes
                .iter()
                .find(|recipe| recipe.recipe_id == id)
                .unwrap();
            assert!(recipe
                .request
                .arguments
                .iter()
                .any(|argument| argument.length_pointer_arg.is_some()));
        }
    }
}
