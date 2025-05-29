use banana_train::BananaTrain;

mod banana_train;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    BananaTrain::new().await.run().await
}
