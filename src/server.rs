use num_bigint::BigUint;
use std::{sync::Mutex, collections::HashMap};
// tonic lib will be generated in build time; need to use 'pub mod' iOT use macro keywords
use tonic::{transport::Server, Code, Request, Response, Status};
pub mod zkp_auth{ //* Make this module available.
    include!("./zkp_auth.rs");
}

use zkp_auth::auth_service_server::{AuthService, AuthServiceServer}; //* Factories
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};

//* Structure for Tonic server
#[derive(Debug, Default)] //* Use in both purpose; debug and default.
pub struct AuthImpl{
    pub user_info_storage: Mutex<HashMap<String,UserInfo>>, //* Insecure due to asynchronous code; need to call mutex to lock this map while updating.
    //* Hash<String, UserInfo>
    //* Mutex will block another thread to access while updating.
}

//* Structure for user information
#[derive(Debug, Default)]
pub struct UserInfo{
    pub username: String,

    //* Registration
    pub y1: BigUint,
    pub y2: BigUint,

    //* authorization
    pub r1: BigUint,
    pub r2: BigUint,

    //* verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl AuthService for AuthImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing Register: {:?}", request);
        //* Originally, fields in request object are private; need to be converted to access those private fields.
        let req = request.into_inner();

        //* Request Processing

        let username = req.username;

        let mut user_info:UserInfo = UserInfo::default();
        user_info.username = username.clone();
        user_info.y1 = BigUint::from_bytes_be(&req.y1);
        user_info.y2 = BigUint:: from_bytes_be(&req.y2);

        //* This information is volatile; will be destroyed after this request ends
            //* need to store temporarily - use hashmap.
        let mut user_info_storage = &mut self.user_info_storage.lock().unwrap(); //* Block another thread to access.
        user_info_storage.insert(username, user_info);

        //* Ended successfully: return successful response
        Ok(Response::new(RegisterResponse{}))
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