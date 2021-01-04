use std::env;
use josekit::{JoseError, jwe::{JweHeader, A128KW}, jwt::{self, JwtPayload}};
// use serde::{Serialize, Deserialize};
use serde_json::{Value};
extern crate dotenv;

fn ch_to_hex(c: &u8) -> u8 {
    match *c as char {
        '0'..='9' => c - ('0' as u8),
        'a'..='z' => c - ('a' as u8) + 10,
        'A'..='Z' => c - ('A' as u8) + 10,
        _ => 0
    }
}

fn str_to_hex(char_array: impl AsRef<[u8]>) -> Vec<u8> {
    let chars = char_array.as_ref().to_vec();
    let mut ret_val = Vec::<u8>::new();
    let mut c: u8 = 0;
    for (i, x) in chars.iter().enumerate() {
        if i %  2== 0 {
            c = ch_to_hex(&x);
        } else {
            c = (c << 4 ) + ch_to_hex(&x);
            ret_val.push(c);
        }
    }
    if chars.len() % 2 != 0 {
        ret_val.push(c);
    }
    ret_val
}

fn encode_auth_token(json: &str, key: Vec<u8>) -> Result<String, JoseError> {
    let mut header = JweHeader::new();
    header.set_token_type("JWT");
    header.set_content_encryption("A128CBC-HS256");

    let mut payload = JwtPayload::new();
    let value : Value = serde_json::from_str(json).unwrap();
    match &value {
        Value::Object(map) => {
            for (key, value) in map.into_iter() {
                payload.set_claim(key, Some(value.clone()))?;
            }
        },
        _ => {
            println!("Not a object")
        }
    }

    let encrypter = A128KW.encrypter_from_bytes(key)?;
    let jwt = jwt::encode_with_encrypter(&payload, &header, &encrypter)?;
    Ok(jwt)
}

fn decode_auth_token(token: &str, key: Vec<u8>) -> Result<String, JoseError> {
    
    let decrypter = A128KW.decrypter_from_bytes(key)?;
    let (payload, _header) = jwt::decode_with_decrypter(&token, &decrypter)?;

    Ok(payload.to_string())
}

fn main() {
    dotenv::dotenv().ok();
    let key_buffer = env::var("KEY_BUFFER").unwrap();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        if args.len() < 2 {
            println!("Command encode or decode needed");
        }
        else {
            match args[1].as_str() {
                "encode" => {
                    println!("encode parameter requires json parameter")
                },
                "decode" => {
                    println!("decode parameter requires authtoken parameter")

                },
                _ => {
                    println!("unknown command {}", args[1])
                }
            }
        }
        return;
    }
 
    match args[1].as_str() {
        "decode" => {
            let key = str_to_hex(key_buffer);
            let json = decode_auth_token(&args[2], key).unwrap();
            println!("{}", json);
        },
        "encode" => {
            let key = str_to_hex(key_buffer);
            let jwt = encode_auth_token(&args[2], key).unwrap();
            println!("{}", jwt);
        },
        _ => {
            println!("unknown command {}", args[1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero() {
        assert_eq!(ch_to_hex(&('0' as u8)), 0);
    }
    #[test]
    fn nine(){
        assert_eq!(ch_to_hex(&('9' as u8)), 9);
    }
    #[test]
    fn ten_uc(){
        assert_eq!(ch_to_hex(&('A' as u8)), 10);
    }
    #[test]
    fn ten_lc(){
        assert_eq!(ch_to_hex(&('a' as u8)), 10);
    }
    #[test]
    fn fifteen_uc(){
        assert_eq!(ch_to_hex(&('F' as u8)), 15);
    }
    #[test]
    fn fifteen_lc(){
       assert_eq!(ch_to_hex(&('f' as u8)), 15);
    }

    #[test]
    fn arr_test_one() {
        assert_eq!(str_to_hex(&(b"f")), vec![15]);
    }

    #[test]
    fn arr_test_two() {
        assert_eq!(str_to_hex(&(b"ff")), vec![255]);
    }
}