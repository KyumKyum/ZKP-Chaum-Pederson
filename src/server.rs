// tonic lib will be generated in build time; need to use 'pub mod' iOT use macro keywords
use tonic::{transport::Server, Code, Request, Response, Status};
pub mod zkp_auth{ //* Make this module available.
    include!("./zkp_auth.rs");
}

use zkp_auth::auth_service_server::{AuthService, AuthServiceServer}; //* Factories
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};

//* Structure for Tonic server
#[derive(Debug, Default)] //* Use in both purpose; debug and default.
struct AuthImpl{}

#[tonic::async_trait]
impl AuthService for AuthImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        todo!()
    }

    async fn create_authentication_challange(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        todo!()
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        todo!()
    }
}

#[tokio::main] //* Async function
async fn main(){
    let addr_local = "127.0.0.1:50051".to_string();

    let auth_impl = AuthImpl::default(); //* Use Default Trait

    println!("🎉🎉 Server is running on http://{}", addr_local);
    Server::builder()
        .add_service(AuthServiceServer::new(auth_impl))
        .serve(addr_local.parse().expect("Cannot convert addr"))
        .await
        .unwrap();



}