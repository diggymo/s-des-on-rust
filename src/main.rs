use rand;
use rand::Rng;
use std::fs;

/**
 * FIXME: パディングしてない
 */
fn main() {
    // ecb_mode();
    // cbc_mode();
    // cfb_mode();
    // ofb_mode();
    ctr_mode();
}

fn ctr_mode() {
    let nonce: u8 = rand::thread_rng().gen_range(0..255);
    let (key1, key2) = generate_key(0b1010000010);

    let plain_text_file = fs::read("./plain.txt").unwrap();

    let mut encrypted_text = plain_text_file
        .into_iter()
        .enumerate()
        .map(|(index, char)| {
            // FIXME: usizeを超えるとpanicする
            let counter = nonce.wrapping_add(index as u8);
            let encrypted = encrypt(counter, key1, key2);
            encrypted ^ char
        })
        .collect::<Vec<_>>();

    // nonceを埋め込む
    encrypted_text.insert(0, nonce);
    fs::write("./ctr.encrypted.txt", encrypted_text).unwrap();

    let encrypted_text_file: Vec<u8> = fs::read("./ctr.encrypted.txt").unwrap();
    // nonceを取り出す
    let mut encrypted_text_file_iter = encrypted_text_file.into_iter();
    let nonce = encrypted_text_file_iter.next().unwrap();

    let decrypted_text = encrypted_text_file_iter
        .enumerate()
        .map(|(index, char)| {
            // FIXME: usizeを超えるとpanicする
            let counter = nonce.wrapping_add(index as u8);
            let encrypted = encrypt(counter, key1, key2);
            encrypted ^ char
        })
        .collect::<Vec<_>>();

    fs::write("./ctr.decrypted.txt", decrypted_text).unwrap();
}

fn ofb_mode() {
    let iv = create_initialized_vector();
    let (key1, key2) = generate_key(0b1010000010);

    let plain_text_file = fs::read("./plain.txt").unwrap();

    // 初期化ベクトルは先頭に付与しておく
    let mut encrypted_text: Vec<u8> = vec![iv];

    let mut next_input = iv;
    for input in plain_text_file.into_iter() {
        let encrypted = encrypt(next_input, key1, key2);
        let mixed = input ^ encrypted;
        encrypted_text.push(mixed);
        next_input = encrypted;
    }

    fs::write("./ofb.encrypted.txt", encrypted_text).unwrap();

    let encrypted_text_file = fs::read("./ofb.encrypted.txt").unwrap();

    let mut encrypted_text_file_iter = encrypted_text_file.into_iter();

    let mut next_input = encrypted_text_file_iter.next().unwrap();
    let mut decrypted_text: Vec<u8> = vec![];
    for input in encrypted_text_file_iter {
        let encrypted: u8 = encrypt(next_input, key1, key2);

        let decrypted = input ^ encrypted;

        next_input = encrypted;
        decrypted_text.push(decrypted);
    }

    fs::write("./ofb.decrypted.txt", decrypted_text).unwrap();
}

fn cfb_mode() {
    let iv = create_initialized_vector();
    let (key1, key2) = generate_key(0b1010000010);

    // 暗号化
    let plain_text_file = fs::read("./plain.txt").unwrap();

    // 初期化ベクトルは先頭に付与しておく
    let mut encrypted_text: Vec<u8> = vec![iv];

    let mut next_input = iv;
    for input in plain_text_file.into_iter() {
        let encrypted = encrypt(next_input, key1, key2);
        let mixed = input ^ encrypted;
        encrypted_text.push(mixed);
        next_input = mixed;
    }

    fs::write("./cfb.encrypted.txt", encrypted_text).unwrap();

    let encrypted_text_file = fs::read("./cfb.encrypted.txt").unwrap();

    let mut encrypted_text_file_iter = encrypted_text_file.into_iter();
    let iv = encrypted_text_file_iter.next().unwrap();

    let mut next_input = iv;
    let mut decrypted_text: Vec<u8> = vec![];
    for input in encrypted_text_file_iter {
        let encrypted: u8 = encrypt(next_input, key1, key2);

        let decrypted = input ^ encrypted;

        next_input = input;
        decrypted_text.push(decrypted);
    }

    fs::write("./cfb.decrypted.txt", decrypted_text).unwrap();
}

fn cbc_mode() {
    let iv = create_initialized_vector();
    let (key1, key2) = generate_key(0b1010000010);

    let plain_text_file = fs::read("./plain.txt").unwrap();

    // 初期化ベクトルは先頭に付与しておく
    let mut encrypted_text: Vec<u8> = vec![iv];
    let mut next_input = iv;
    for input in plain_text_file.into_iter() {
        let mixed = input ^ next_input;
        let encrypted = encrypt(mixed, key1, key2);
        next_input = encrypted;
        encrypted_text.push(encrypted);
    }

    fs::write("./cbc.encrypted.txt", encrypted_text).unwrap();

    let encrypted_text_file = fs::read("./cbc.encrypted.txt").unwrap();

    let mut encrypted_text_file_iter = encrypted_text_file.into_iter();
    let iv = encrypted_text_file_iter.next().unwrap();

    let mut next_input = iv;
    let mut decrypted_text: Vec<u8> = vec![];
    for input in encrypted_text_file_iter {
        let decrypted: u8 = decrypt(input, key1, key2);
        let plain = decrypted ^ next_input;
        next_input = input;
        decrypted_text.push(plain);
    }

    fs::write("./cbc.decrypted.txt", decrypted_text).unwrap();
}

fn ecb_mode() {
    let (key1, key2) = generate_key(0b1010000010);

    let plain_text_file = fs::read("./plain.txt").unwrap();

    let encrypted_text = plain_text_file
        .into_iter()
        .map(|char| encrypt(char, key1, key2))
        .collect::<Vec<_>>();

    fs::write("./ecb.encrypted.txt", encrypted_text).unwrap();

    let encrypted_text_file = fs::read("./ecb.encrypted.txt").unwrap();

    let decrypted_text = encrypted_text_file
        .iter()
        .map(|char| decrypt(char.clone(), key1, key2))
        .collect::<Vec<_>>();

    fs::write("./ecb.decrypted.txt", decrypted_text).unwrap();
}

fn create_initialized_vector() -> u8 {
    let mut rng = rand::thread_rng();
    let initialized_vector = rng.gen_range(0..255);
    return initialized_vector;
}
fn generate_key(input: u16) -> (u8, u8) {
    let after_p10 = p10_permutation(input);
    let [left_p10, right_p10] = split_10bit(after_p10);
    println!("{:10b}", after_p10);
    let left_shifted = (left_p10 & 0b1111) << 1 | ((left_p10 & (1 << 4)) >> 4);
    let right_shifted = (right_p10 & 0b1111) << 1 | ((right_p10 & (1 << 4)) >> 4);

    let key1 = p8_permutation(left_shifted << 5 | right_shifted);

    let left_shifted = (left_shifted & 0b111) << 2 | ((left_shifted & (0b11 << 3)) >> 3);
    let right_shifted = (right_shifted & 0b111) << 2 | ((right_p10 & (0b11 << 3)) >> 3);

    let key2 = p8_permutation(left_shifted << 5 | right_shifted);

    return (key1, key2);
}

fn p10_permutation(input: u16) -> u16 {
    let bit10 = is_true_bit(input, 0) as u16;
    let bit9 = is_true_bit(input, 1) as u16;
    let bit8 = is_true_bit(input, 2) as u16;
    let bit7 = is_true_bit(input, 3) as u16;
    let bit6 = is_true_bit(input, 4) as u16;
    let bit5 = is_true_bit(input, 5) as u16;
    let bit4 = is_true_bit(input, 6) as u16;
    let bit3 = is_true_bit(input, 7) as u16;
    let bit2 = is_true_bit(input, 8) as u16;
    let bit1 = is_true_bit(input, 9) as u16;

    return (bit6)
        | bit8 << 1
        | bit9 << 2
        | bit1 << 3
        | bit10 << 4
        | bit4 << 5
        | bit7 << 6
        | bit2 << 7
        | bit5 << 8
        | bit3 << 9;
}

fn p8_permutation(input: u16) -> u8 {
    let bit10 = is_true_bit(input, 0) as u8;
    let bit9 = is_true_bit(input, 1) as u8;
    let bit8 = is_true_bit(input, 2) as u8;
    let bit7 = is_true_bit(input, 3) as u8;
    let bit6 = is_true_bit(input, 4) as u8;
    let bit5 = is_true_bit(input, 5) as u8;
    let bit4 = is_true_bit(input, 6) as u8;
    let bit3 = is_true_bit(input, 7) as u8;
    let bit2 = is_true_bit(input, 8) as u8;
    let bit1 = is_true_bit(input, 9) as u8;

    return (bit9)
        | bit10 << 1
        | bit5 << 2
        | bit8 << 3
        | bit4 << 4
        | bit7 << 5
        | bit3 << 6
        | bit6 << 7;
}

fn encrypt(plain_text: u8, key1: u8, key2: u8) -> u8 {
    let after_ip = initial_permutation(plain_text);
    let after_fx = fx(key1, after_ip);
    let after_part1 = swap_8bit(after_fx);
    let after_fx = fx(key2, after_part1);
    let result = final_permutation(after_fx);
    result
}

fn decrypt(cipher_text: u8, key1: u8, key2: u8) -> u8 {
    let after_ip = initial_permutation(cipher_text);
    let after_fx = fx(key2, after_ip);
    let after_part1 = swap_8bit(after_fx);
    let after_fx = fx(key1, after_part1);
    let result = final_permutation(after_fx);
    result
}

fn fx(key: u8, input: u8) -> u8 {
    let [left_ip, right_ip] = split_8bit(input);

    let after_ep = expanded_permutation(right_ip);

    let after_ep_xor_key = key ^ after_ep;
    let [left_ep, right_ep] = split_8bit(after_ep_xor_key);

    let left_sbox = sbox_left(left_ep);
    let right_sbox = sbox_right(right_ep);
    let after_sbox = left_sbox << 2 | right_sbox;

    let after_p4 = p4_permutation(after_sbox);

    let after_p4_xor = after_p4 ^ left_ip;
    let result = (after_p4_xor << 4) | right_ip;

    return result;
}

fn swap_8bit(data: u8) -> u8 {
    return (data >> 4) | ((data << 4) & 0b11110000);
}

fn initial_permutation(data: u8) -> u8 {
    let bit8 = is_true_bit(data as u16, 0) as u8;
    let bit7 = is_true_bit(data as u16, 1) as u8;
    let bit6 = is_true_bit(data as u16, 2) as u8;
    let bit5 = is_true_bit(data as u16, 3) as u8;
    let bit4 = is_true_bit(data as u16, 4) as u8;
    let bit3 = is_true_bit(data as u16, 5) as u8;
    let bit2 = is_true_bit(data as u16, 6) as u8;
    let bit1 = is_true_bit(data as u16, 7) as u8;

    return (bit7)
        | bit5 << 1
        | bit8 << 2
        | bit4 << 3
        | bit1 << 4
        | bit3 << 5
        | bit6 << 6
        | bit2 << 7;
}

fn final_permutation(data: u8) -> u8 {
    let bit8 = is_true_bit(data as u16, 0) as u8;
    let bit7 = is_true_bit(data as u16, 1) as u8;
    let bit6 = is_true_bit(data as u16, 2) as u8;
    let bit5 = is_true_bit(data as u16, 3) as u8;
    let bit4 = is_true_bit(data as u16, 4) as u8;
    let bit3 = is_true_bit(data as u16, 5) as u8;
    let bit2 = is_true_bit(data as u16, 6) as u8;
    let bit1 = is_true_bit(data as u16, 7) as u8;

    return (bit6)
        | bit8 << 1
        | bit2 << 2
        | bit7 << 3
        | bit5 << 4
        | bit3 << 5
        | bit1 << 6
        | bit4 << 7;
}

fn expanded_permutation(data: u8) -> u8 {
    let bit4 = is_true_bit(data as u16, 0) as u8;
    let bit3 = is_true_bit(data as u16, 1) as u8;
    let bit2 = is_true_bit(data as u16, 2) as u8;
    let bit1 = is_true_bit(data as u16, 3) as u8;

    return (bit1)
        | bit4 << 1
        | bit3 << 2
        | bit2 << 3
        | bit3 << 4
        | bit2 << 5
        | bit1 << 6
        | bit4 << 7;
}

fn sbox_left(data: u8) -> u8 {
    let sbox0: [[u8; 4]; 4] = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]];
    let row = ((data & (1 << 3)) >> 2) | (data & 1);
    let column = ((data & (1 << 2)) >> 1) | ((data & (1 << 1)) >> 1);
    return sbox0[row as usize][column as usize];
}

fn sbox_right(data: u8) -> u8 {
    let sbox1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]];
    let row = ((data & (1 << 3)) >> 2) | (data & 1);
    let column = ((data & (1 << 2)) >> 1) | ((data & (1 << 1)) >> 1);
    return sbox1[row as usize][column as usize];
}

fn p4_permutation(data: u8) -> u8 {
    let bit_4 = is_true_bit(data as u16, 0) as u8;
    let bit_3 = is_true_bit(data as u16, 1) as u8;
    let bit_2 = is_true_bit(data as u16, 2) as u8;
    let bit_1 = is_true_bit(data as u16, 3) as u8;

    return (bit_1) | bit_3 << 1 | bit_4 << 2 | bit_2 << 3;
}

fn split_8bit(data: u8) -> [u8; 2] {
    let left = data >> 4;
    let right = data & 0b00001111;
    [left, right]
}

fn split_10bit(data: u16) -> [u16; 2] {
    let left = data >> 5;
    let right = data & 0b0000011111;
    [left, right]
}

fn is_true_bit(key: u16, bit: u8) -> bool {
    (key & 1 << bit) != 0
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn convert_boolean_to_u8() {
        assert_eq!(true as u8, 1);
        assert_eq!(false as u8, 0);
    }

    #[test]
    fn test_initial_permutation() {
        let result = initial_permutation(0b10010111);
        assert_eq!(result, 0b01011101);
    }

    #[test]
    fn test_split() {
        let [left, right] = split_8bit(0b00011010);
        assert_eq!(left, 0b0001);
        assert_eq!(right, 0b1010);
    }

    #[test]
    fn test_expanded_permutation() {
        let result = expanded_permutation(0b1101);
        assert_eq!(result, 0b11101011);
    }

    #[test]
    fn test_sbox_left() {
        let result = sbox_left(0b0001);
        assert_eq!(result, 3);
    }

    #[test]
    fn test_sbox_right() {
        let result = sbox_right(0b0110);
        assert_eq!(result, 3);
    }

    #[test]
    fn test_p4_permutation() {
        let result = p4_permutation(0b0101);
        assert_eq!(result, 0b1100);
    }

    #[test]
    fn test_swap() {
        assert_eq!(swap_8bit(0b00011010), 0b10100001);
    }

    #[test]
    fn test_fx() {
        let result = fx(0b10100100, 0b01011101);
        assert_eq!(result, 0b10101101);
    }

    #[test]
    fn test_encrypt() {
        let plain_text = 0b10010111;
        let key1 = 0b10100100;
        let key2 = 0b01000011;
        let result = encrypt(plain_text, key1, key2);
        assert_eq!(result, 0b00111000);
    }

    #[test]
    fn test_decrypt() {
        let cipher_text = 0b00111000;
        let key1 = 0b10100100;
        let key2 = 0b01000011;
        let result = decrypt(cipher_text, key1, key2);
        assert_eq!(result, 0b10010111);
    }

    #[test]
    fn test_key_generate() {
        let (key1, key2) = generate_key(0b1010000010);

        assert_eq!(key1, 0b10100100);
        assert_eq!(key2, 0b01000010);
    }

    #[test]
    fn test_ecb_mode() {
        ecb_mode();
    }

    #[test]
    fn test_cbc_mode() {
        cbc_mode();
    }

    #[test]
    fn test_cfb_mode() {
        cfb_mode();
    }

    #[test]
    fn test_ofb_mode() {
        ofb_mode();
    }

    #[test]
    fn test_increment() {
        let a: u8 = 0b11111111;
        assert_eq!(a.wrapping_add(1), 0);
    }

    #[test]
    fn test_ctr_mode() {
        ctr_mode();
    }
}
