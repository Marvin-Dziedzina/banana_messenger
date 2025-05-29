pub struct BananaTrain {}

impl BananaTrain {
    pub async fn new() -> Self {
        netwrk::
        Self {}
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        loop {
            tokio::task::yield_now().await;
        }
    }
}
