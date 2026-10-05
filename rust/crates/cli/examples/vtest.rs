use dictcrack_core::{archive, verifier};
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let pwd = std::env::args().nth(2).unwrap();
    let info = archive::parse(&path);
    let v = verifier::create_native(&info, &path).unwrap();
    println!("{} => {}", v.describe(), v.verify(&pwd));
}
