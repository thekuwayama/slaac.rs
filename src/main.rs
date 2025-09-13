mod rs;

fn main() {
    match rs::resolve_router_prefix() {
        Ok(prefix) => println!("{:?}", prefix), 
        Err(msg) => println!("{}", msg),
    };
}
