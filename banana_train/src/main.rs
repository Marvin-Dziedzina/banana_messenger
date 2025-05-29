use banana_train::BananaTrain;

mod banana_train;

#[tokio::main]
async fn main() {
    let banana_train = BananaTrain::new();
}
