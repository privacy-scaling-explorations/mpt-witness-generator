use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn GetProofs(path: GoString) -> *const c_char;
}

#[repr(C)]
struct GoString {
    a: *const c_char,
    b: i64,
}

fn main() {
    println!("Hello, world!");

    // let c_path = CString::new(path).expect("CString::new failed");
    let c_path = CString::new("test test").expect("CString::new failed");
    let ptr = c_path.as_ptr();
    let go_string = GoString {
        a: ptr,
        b: c_path.as_bytes().len() as i64,
    };
    let result = unsafe { GetProofs(go_string) };
    let c_str = unsafe { CStr::from_ptr(result) };
    let string = c_str.to_str().expect("Error translating from library");
    println!("{:?}", string);
}
