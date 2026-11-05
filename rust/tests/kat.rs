//! Known-answer tests. Standard vectors (GB/T 32905, GB/T 32907, GB/T 32918.5) plus outputs
//! captured from the pre-optimization implementation (commit 3397c6d) for fixed inputs;
//! the deterministic ciphertexts below were captured with the random nonce pinned.

use gm_rust::sm2::SM2;
use gm_rust::sm2::bigint256::BigInt256;
use gm_rust::sm2::point::ECPoint;
use gm_rust::sm3::Sm3;
use gm_rust::sm4::SM4;

fn pattern(n: usize) -> String {
    (0..n)
        .map(|i| b"abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + n) % 36] as char)
        .collect()
}

fn sm3_hex(data: &[u8]) -> String {
    let mut h = Sm3::new();
    h.update(data);
    h.finish();
    h.hash_hex_upper().to_string()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// GB/T 32905-2016 appendix A.
#[test]
fn sm3_standard_vectors() {
    assert_eq!(
        sm3_hex(b"abc"),
        "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
    );
    assert_eq!(
        sm3_hex("abcd".repeat(16).as_bytes()),
        "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732"
    );
}

const SM3_CAPTURED: &[(usize, &str)] = &[
    (
        0,
        "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B",
    ),
    (
        1,
        "18EC3B715647A14C4B5D7FE870F6AC237C61BBCF8D56062A74F0824B5218A042",
    ),
    (
        3,
        "9430DAC0C3C0386AEA3E0085E9FF2744D5A5591D723F1E7E58B6B0443F0CF54F",
    ),
    (
        55,
        "6D05D9FCC8AA0D72062B7DDBA720095F56B651F2BBFFDEB3DABBE7F78F904DE5",
    ),
    (
        56,
        "667E559E56CD5F4C34D0ECB535BDCF6153781A64BAF34DE54CDB917531688F7B",
    ),
    (
        63,
        "C414EE312DF4240219DDBF6DB811CE80ED0FC2C2771E2FBE91F8EB5D38970283",
    ),
    (
        64,
        "581A258238C5A7425777FAE222187B90948ADCED144EFE7104E6E2BA5E6F6B8B",
    ),
    (
        65,
        "3A92829A1394CCBC0CB38FAE9FCF1A75FCBB3DAE00CC7E702203D0D41C25A773",
    ),
    (
        119,
        "CC8F5BAF54A07A173ADD18F21442209D6826932D9DBFF66729B2D166AA1C55DB",
    ),
    (
        120,
        "E67D5B31D6F0F5EC2DCDF368E5F86B2BFAD6D828C61918967D9ED28E9473F966",
    ),
    (
        127,
        "687ED96840D363691D074106F999A651BFD57F1272C8463C68CB2B57A296F439",
    ),
    (
        128,
        "25261E4CD93FC78EC3828597CB9FAC85ACBE4CC29D63C1CE77525DFB7C45DA51",
    ),
    (
        129,
        "DDEF76E25FC0795F289ADBE792ACA3AEBBC6692A6B79FD0F675F5301DD5A0AE5",
    ),
    (
        1000,
        "0EAD4189CEBCCF07A87234A723D8B8B53857FC2345EBC9F74B062C4E39ED1D17",
    ),
    (
        4096,
        "04C26717FE4248C57B5B64E0DE619B948812BC1F5880668196F9B2631512B47A",
    ),
    (
        100000,
        "9DD57FF6D32013639E33D61F03EE314DDB37F203689A16C6077D7197130452C1",
    ),
];

#[test]
fn sm3_captured_vectors() {
    for (len, expected) in SM3_CAPTURED {
        assert_eq!(sm3_hex(pattern(*len).as_bytes()), *expected, "len {len}");
    }
}

/// All ways of splitting a message over `update`/`update_byte` must agree.
#[test]
fn sm3_streaming_is_split_invariant() {
    let msg = pattern(300);
    let expected = sm3_hex(msg.as_bytes());
    for split in 0..=msg.len() {
        let mut h = Sm3::new();
        h.update(&msg.as_bytes()[..split]);
        h.update(&msg.as_bytes()[split..]);
        h.finish();
        assert_eq!(h.hash_hex_upper(), expected, "split {split}");
    }
    let mut h = Sm3::new();
    for b in msg.bytes() {
        h.update_byte(b);
    }
    h.finish();
    assert_eq!(h.hash_hex_upper(), expected);
}

/// `finish` resets the state for reuse and the result stays readable.
#[test]
fn sm3_finish_resets_state() {
    let mut h = Sm3::new();
    // Before anything is fed, the digest is that of the empty message.
    assert_eq!(
        h.hash_hex_upper(),
        "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B"
    );
    h.update_str("abc").finish();
    let first = h.hash_hex_upper().to_string();
    h.update_str("abc").finish();
    assert_eq!(h.hash_hex_upper(), first);
    assert_eq!(unhex(&first), h.hash_bytes());
}

/// Hashes `mib` MiB of zeros through the streaming interface.
fn sm3_zeros_mib(mib: usize) -> String {
    let chunk = vec![0u8; 1 << 20];
    let mut h = Sm3::new();
    for _ in 0..mib {
        h.update(&chunk);
    }
    h.finish();
    h.hash_hex_upper().to_string()
}

/// The length field is 64 bits: correct at and beyond 2^32 bits. Values independent of this
/// library. Slow, so opt-in.
#[test]
#[ignore = "hashes 1.5 GiB; run with --release -- --ignored"]
fn sm3_long_messages() {
    assert_eq!(
        sm3_zeros_mib(512),
        "7927CA8884A535D9A4D80986F7C478A790013EE370836DFB86A36B4443C86533"
    );
    assert_eq!(
        sm3_zeros_mib(1024),
        "F1ADF167041F7B4DDE929A73E500A642FBD03B9B457ADFE9EE15708EA34D12B3"
    );
}

/// GB/T 32907-2016 example 1, reached through the CBC API: choosing IV = P xor M makes the first
/// ciphertext block equal to E(P) for an ASCII message block M.
#[test]
fn sm4_standard_vector_through_cbc() {
    let key = unhex("0123456789abcdeffedcba9876543210");
    let plain = key.clone();
    let m = *b"ABCDEFGHIJKLMNOP";
    let iv: Vec<u8> = plain.iter().zip(m).map(|(p, x)| p ^ x).collect();
    let mut sm4 = SM4::new();
    sm4.set_key(&key, &iv).unwrap();
    let ct = sm4.encrypt(core::str::from_utf8(&m).unwrap()).unwrap();
    assert_eq!(&ct[..32], "681edf34d206965e86b3e94f536e4246");
}

const SM4_CAPTURED: &[(usize, &str)] = &[
    (0, "3feb30a8cb3414d4c160c7927a11e6d9"),
    (1, "4dff63b85ea97d4fae0f2bafd8a2c711"),
    (15, "53e369ea547dd9bf1bb57edf79e8a89c"),
    (
        16,
        "1d7ddca8571c28126f2ea783203fad69932c7d95de36c1fc100149dd0f0ed009",
    ),
    (
        17,
        "f8b1c6c17892865f5128dd8021d59bf22442028ba2a499f80700a8b2adb17d71",
    ),
    (
        31,
        "eacc9442c548002acbeb667c7715b4444605874c5864357337531d46ca826c80",
    ),
    (
        32,
        "3151c147b4c35c4de2c4335e2babae6e80124a5abae47e425591280a05466ba60a2de2230eb1bbcc437cfe40809ed018",
    ),
    (
        33,
        "805b733b68a49ce85534d831dd0bb22ab603b32ad1c29bfaab69e3e28e6799293ba63bed4369c8b999ade0477572f888",
    ),
    (
        63,
        "1aa3b072bc12fea8e453dbae621bdf57229bc7bb55a649b1578b44eb2d8607e84001c76d8c351f356ca456d2c77d960da89aa3949d1eb56ba7b96e5f3a50b9ee",
    ),
    (
        64,
        "sm3:91B2ADF0393E7081D56E153D589FEE779F20AA47E804847936C9F32EA309D117",
    ),
    (
        65,
        "sm3:9F283D67D9B4285775952CE0A0EDF0D2E151FBDFFF7B6CF0BB3C5F889D8F198F",
    ),
    (
        127,
        "sm3:06FF0378EFC35707AC31F67A3B528368B3BB378C65CD1BDB67F3A265E8E43245",
    ),
    (
        128,
        "sm3:E6ED8CDD1B9640242ED77CE84DDBF9A2B05A2DFB04760F802F39DE37DB4941D1",
    ),
    (
        129,
        "sm3:81A308E5834D4BE0597B07428F0A83EF2575F12FA0FE449C5B55CF03F0324304",
    ),
    (
        200,
        "sm3:0A6302190B9BD9F30F598B0446D45C53C2E740BF3A93CCF7DB1F461A7551E093",
    ),
    (
        1000,
        "sm3:61ECBD2E01EAE81CD9D46823C0C36107C1747A7961A1D8650706AE1E7D5FCB3A",
    ),
];

#[test]
fn sm4_captured_vectors() {
    let mut sm4 = SM4::new();
    sm4.set_key(b"0123456789abcdef", b"fedcba9876543210")
        .unwrap();
    for (len, expected) in SM4_CAPTURED {
        let plain = pattern(*len);
        let ct = sm4.encrypt(&plain).unwrap();
        match expected.strip_prefix("sm3:") {
            Some(hash) => assert_eq!(sm3_hex(ct.as_bytes()), hash, "len {len}"),
            None => assert_eq!(ct, *expected, "len {len}"),
        }
        assert_eq!(sm4.decrypt(&ct).unwrap(), plain, "len {len}");
    }
}

/// Keys and IVs must be exactly 16 bytes, and an instance without a key does nothing.
#[test]
fn sm4_requires_a_full_key_and_iv() {
    let mut sm4 = SM4::new();
    assert!(sm4.encrypt("hello world").is_err());
    assert!(sm4.decrypt("00000000000000000000000000000000").is_err());
    assert!(sm4.set_key(b"short", &[0; 16]).is_err());
    assert!(sm4.set_key(&[0; 16], b"short").is_err());
    assert!(
        sm4.encrypt("hello world").is_err(),
        "a failed set_key keys nothing"
    );

    sm4.set_key(&[1; 16], &[2; 16]).unwrap();
    let before = sm4.encrypt("hello world").unwrap();
    assert!(sm4.set_key(&[3; 17], &[4; 16]).is_err());
    assert_eq!(
        sm4.encrypt("hello world").unwrap(),
        before,
        "a failed set_key changes nothing"
    );
}

#[test]
fn sm4_error_behaviour() {
    let mut sm4 = SM4::new();
    sm4.set_key(b"0123456789abcdef", b"fedcba9876543210")
        .unwrap();
    let msg = |c: &str| sm4.decrypt(c).unwrap_err().to_string();
    assert_eq!(msg("abc"), "Invalid hex string");
    assert_eq!(msg("zz"), "Invalid hex string");
    assert_eq!(msg("+f"), "Invalid hex string");
    assert_eq!(msg("é1"), "Invalid hex string");
    // Wrong lengths and bad padding are one error.
    assert_eq!(msg(""), "Invalid padding");
    assert_eq!(msg("00"), "Invalid padding");
    assert_eq!(msg("00000000000000000000000000000000"), "Invalid padding");
    assert_eq!(msg("AA"), "Invalid hex string");
}

/// Scalar multiples of G, including 0, n-1, n, n+1 and 2^256-1.
const EC_MULTIPLES: &[(&str, &str)] = &[
    ("0", "00"),
    (
        "1",
        "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    ),
    (
        "2",
        "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3",
    ),
    (
        "3",
        "04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6",
    ),
    (
        "F",
        "04f73b839f13912c1a3291676c38d393243b424f35f0ecce4c461b1bbcb80f829c32ec7722695dc7cf5ee9fab985c12455dc2e788fb170aa144c3533771db0955e",
    ),
    (
        "10",
        "0435648233f554ae51bbce44ef5db3e419ea133cd248a93e2555645bbc8704fb6804d7ac60f6d975ef6117bca9ce885dd6154b1870a6a651664411a9a30eca2046",
    ),
    (
        "11",
        "04dd18aa4aec26eac41c993f01115c57f7bf5113ab85b5ed4436969f8b77125e6a161e5851969da8223361493f76fac50f6cce6001d7c0b853e0180d54d4ae2221",
    ),
    (
        "1F",
        "0408daae840b2a43ebd6b48259b69e853027d053c0f150fe10ac995c5066bdaaa580cc0a980495af87c1b8e58150da662df7dc310560bbe83a2458b9e3c73bf657",
    ),
    (
        "20",
        "0425d3debd0950d180a6d5c2b5817f2329791734cd03e5565ca32641e56024666c92d99a70679d61efb938c406dd5cb0e10458895120e208b4d39e100303fa10a2",
    ),
    (
        "21",
        "04a1aa7f4a428089084624f85fe9b7cb83451641e8455eedb66d69b1bd07837dc93d420dee447499cfeb15fccc636948306e67fd81941c6a60c3c8bd75b5fe25de",
    ),
    (
        "8000000000000000000000000000000000000000000000000000000000000000",
        "04dcb53eb5b07c0513881158cfe779f44aa3fa4bfbdaeda1eb48bb387a1529db42571adb13e629a820f0ab2ad4e5fd9181083d8d22bc54738063d0aca20746e1aa",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "04b3217d884bc175e6ba6b360eb0e6d4396eaea725c3d66e87bfa5beb6c0d3456ba5199445c54b56602aa60025e1907bfd26b30e867db6c58a034263ae4a2e27c2",
    ),
    (
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122",
        "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c743c8c95c0b098863a642311c9496deac2f56788239d5b8c0fd20cd1adec60f5f",
    ),
    (
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54121",
        "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52ce481818337e760997aca31f07150e429217b3e6d093718f9087f2c568f5dc3c",
    ),
    (
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54103",
        "0425d3debd0950d180a6d5c2b5817f2329791734cd03e5565ca32641e56024666c6d26658e98629e1046c73bf922a34f1efba776addf1df74c2c61effcfc05ef5d",
    ),
    (
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        "00",
    ),
    (
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124",
        "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
    ),
    (
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
    ),
];

#[test]
fn sm2_generator_multiples() {
    for (k, expected) in EC_MULTIPLES {
        let scalar = BigInt256::from_hex(k);
        // Outside [1, n-2] the value is not a private key, whatever its multiple of G.
        let n_minus_1 = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122";
        let is_key = !scalar.is_zero() && scalar < BigInt256::from_hex(n_minus_1);
        let as_key = SM2::get_public_key(&scalar);
        assert_eq!(as_key.is_infinity(), !is_key, "k = {k}");
        if is_key {
            assert_eq!(as_key.to_hex_encoded(), *expected, "k = {k}");
        }
        assert_eq!(
            ECPoint::generator().multiply(&scalar).to_hex_encoded(),
            *expected,
            "k = {k}"
        );
    }
}

const GBT_D: &str = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
const GBT_PUB: &str = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13";
/// GB/T 32918.5 sample: k = 59276E27...BC21, ID = 1234567812345678, M = "message digest".
const GBT_SIG: &str = "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3hb1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa";
const PINNED_CT: &str = "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd876621886ca989ca9c7d58087307ca93092d651efa";
const PINNED_CT100: &str = "04ddf092555409c19dfdbe86a75c139906a80198337744ee78cd27e384d9fcaf15847d18ffb38e87065cd6b6e9c12d2922037937707d6a49a2223b949657e52bc188a2b4b1b906c1eb848dcf5bbc21ed6f3acb124a1d0082fab7b0d48dc19a84f157952eeb57eaa750468c0866cb1dd9161e657750a5710c3aebf56e7af8121218dadf42b18daf664f81995894137dda18707f4447db546820583a3bbdd1959d6b6726e3a46f1c00d9c8a237abc2ccf965a38f6a9e6e3337f471ce2d43203e8d38f8b6be81";

#[test]
fn sm2_signature_vector() {
    let id = "1234567812345678";
    assert!(SM2::verify(id, GBT_SIG, "message digest", GBT_PUB));
    assert!(!SM2::verify(id, GBT_SIG, "message digesT", GBT_PUB));
    assert!(!SM2::verify(
        "1234567812345679",
        GBT_SIG,
        "message digest",
        GBT_PUB
    ));
    let fresh = SM2::sign(id, "message digest", GBT_D).unwrap();
    assert!(SM2::verify(id, &fresh, "message digest", GBT_PUB));
    assert_eq!(fresh.len(), 129);
    assert_eq!(&fresh[64..65], "h");
}

#[test]
fn sm2_decrypts_pinned_ciphertexts() {
    assert_eq!(
        SM2::decrypt(PINNED_CT, GBT_D).unwrap(),
        "encryption standard"
    );
    assert_eq!(SM2::decrypt(PINNED_CT100, GBT_D).unwrap(), pattern(100));
}

#[test]
fn sm2_decrypt_rejects_tampering() {
    let mut tampered = PINNED_CT.to_string();
    let last = tampered.pop().unwrap();
    tampered.push(if last == '0' { '1' } else { '0' });
    assert_eq!(
        SM2::decrypt(&tampered, GBT_D).unwrap_err(),
        "Decryption verification failed"
    );
    assert_eq!(
        SM2::decrypt("04", GBT_D).unwrap_err(),
        "Ciphertext too short"
    );
}

const KEX_CAPTURED: &[(usize, &str, &str, &str)] = &[
    (
        16,
        "b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e",
        "f02f9068ad13e14f2b2602e0dfb2504f",
        "daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6",
    ),
    (
        32,
        "b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e",
        "f02f9068ad13e14f2b2602e0dfb2504ff5fabef8555364b7374436e8566d02aa",
        "daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6",
    ),
    (
        33,
        "b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e",
        "f02f9068ad13e14f2b2602e0dfb2504ff5fabef8555364b7374436e8566d02aa57",
        "daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6",
    ),
    (
        100,
        "b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e",
        "f02f9068ad13e14f2b2602e0dfb2504ff5fabef8555364b7374436e8566d02aa5704021bc20a93dbefc42d1978da9b6830d8ad136daf44480cb8f31eeed3961cbdc1ef4b8311581d0b72ff21f909f97f02254bd53cd70998b5bf94f5806c84767ef4609f",
        "daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6",
    ),
];
const KEX_V: &str = "04588d82da2f0e75a042aab58a707c725e203d1bf1cb8eff56e37af32c24665267e85d7572801c598eeebc061347821a568895aef6fb8448fbef16845cfcc2e6f4";
const KEX_ZA: &str = "5d0b1182e1cee9093e96b6bdbf2e32f854d5c753e2ce9865d4984b8b70a8ae2b";
const KEX_ZB: &str = "441bf12aca4164c866bf282787dfc63e0cc8268fa34d435491b0cbc7f6ddbd5e";

#[test]
fn sm2_key_exchange_vectors() {
    let (id_a, id_b) = ("ALICE123@YAHOO.COM", "BILL456@YAHOO.COM");
    let d_a =
        BigInt256::from_hex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
    let ra =
        BigInt256::from_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
    let d_b =
        BigInt256::from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
    let rb =
        BigInt256::from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
    let (p_a, r_a) = (SM2::get_public_key(&d_a), SM2::get_public_key(&ra));
    let (p_b, r_b) = (SM2::get_public_key(&d_b), SM2::get_public_key(&rb));
    for (len, sb, key, sa) in KEX_CAPTURED {
        let b = SM2::get_sb(*len, &p_a, &r_a, &p_b, &d_b, &r_b, &rb, id_a, id_b);
        assert!(b.success);
        assert_eq!(b.sb.as_deref(), Some(*sb));
        assert_eq!(b.kb.as_deref(), Some(*key));
        let v = b.v.as_ref().unwrap();
        assert_eq!(v.to_hex_encoded(), KEX_V);
        assert_eq!(b.za.as_deref(), Some(&unhex(KEX_ZA)[..]));
        assert_eq!(b.zb.as_deref(), Some(&unhex(KEX_ZB)[..]));
        let a = SM2::get_sa(
            *len,
            &p_b,
            &r_b,
            &p_a,
            &d_a,
            &r_a,
            &ra,
            id_a,
            id_b,
            &unhex(sb),
        );
        assert!(a.success);
        assert_eq!(a.sa.as_deref(), Some(*sa));
        assert_eq!(a.ka.as_deref(), Some(*key));
        assert!(SM2::check_sa(
            v,
            b.za.as_ref().unwrap(),
            b.zb.as_ref().unwrap(),
            &r_a,
            &r_b,
            &unhex(sa)
        ));
    }
    let wrong = SM2::get_sa(
        16, &p_b, &r_b, &p_a, &d_a, &r_a, &ra, id_a, id_b, &[0u8; 32],
    );
    assert!(!wrong.success);
    assert!(wrong.message.is_some());
}
