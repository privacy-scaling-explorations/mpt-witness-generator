// use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn GetProofs(str: *const c_char) -> *const c_char;
}

fn main() {
    println!("Hello, world!");

    let data = r#"
        {
            "Keys": ["0x12", "0x21"],
            "Values": ["0x1123e2", "0xa21"],
            "ToBeModifiedKey": "0x12",
            "ToBeModifiedValue": "0xaa"
        }"#;

    let c_config = CString::new(data).expect("invalid config");

    let result = unsafe { GetProofs(c_config.as_ptr()) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let string = c_str.to_str().expect("Error translating from library");
    println!("{:?}", string);
}
