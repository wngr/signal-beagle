fn main() {
    prost_build::compile_protos(&["proto/Backups.proto"], &["proto/"]).unwrap();
}
