fn main() {
    let names: Vec<String> = std::env::args().skip(1).collect();
    if names.len() == 0 {
        println!("no names");
        return;
    }
    for i in 0..names.len() {
        println!("hello, {}", names[i]);
    }
}
