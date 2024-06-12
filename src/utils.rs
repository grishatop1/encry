use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::PathBuf;

pub fn append_ext(ext: impl AsRef<OsStr>, path: &PathBuf) -> PathBuf {
    let mut os_string: OsString = path.into();
    os_string.push(".");
    os_string.push(ext.as_ref());
    os_string.into()
}