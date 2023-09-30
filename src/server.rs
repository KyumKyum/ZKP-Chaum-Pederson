use num_bigint::BigUint;
use std::{sync::Mutex, collections::HashMap};
use zkp_cp::ZKP;
// tonic lib will be generated in build time; need to use 'pub mod' iOT use macro keywords
use tonic::{transport::Server, Code, Request, Response, Status};

pub mod zkp_auth{ //* Make this module available.
    include!("./zkp_auth.rs");
}

use zkp_auth::auth_service_server::{AuthService, AuthServiceServer};
use zkp_chaum_pedersen::zkp_cp;
//* Factories
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest, RegisterResponse};

//* Structure for Tonic server
#[derive(Debug, Default)] //* Use in both purpose; debug and default.
pub struct AuthImpl{
    pub user_info_storage: Mutex<HashMap<String,UserInfo>>, //* Insecure due to asynchronous code; need to call mutex to lock this map while updating.
    //* Hash<String, UserInfo>
    //* Mutex will block another thread to access while updating.
    pub auth_id_stroage: Mutex<HashMap<String,String>>,
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

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let req = request.into_inner();
        let username = req.username;

        //* Storage
        let mut user_info_storage = &mut self.user_info_storage.lock().unwrap();
        let mut auth_id_storage = &mut self.auth_id_stroage.lock().unwrap();

        //* Some: Option[]; indicated that some value 'exists' <- opposite of None()
        //* If following value exists, do the following routine.
        if let Some(user_info) = user_info_storage.get_mut(&username) {
            user_info.r1 = BigUint::from_bytes_be(&req.r1);
            user_info.r2 = BigUint::from_bytes_be(&req.r2);

            let (_,_,_,q) = ZKP::get_const();

            let aid = ZKP::gen_rand_str(12);
            let c = ZKP::gen_rand(&q);
            user_info.c = c.clone();

            auth_id_storage.insert(aid.clone(), username.clone()); //* Store authid - username match, later will used for verification.
            Ok(Response::new(AuthenticationChallengeResponse{ auth_id: aid, c: c.to_bytes_be()}))
        } else {
            //* None of the user exists
            Err(Status::new(Code::NotFound, format!("User: {} not found", username)))
        }


    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let req = request.into_inner();
        let aid = req.auth_id;
        let s = BigUint::from_bytes_be(&req.s);
        //* Storage
        let mut auth_id_storage = &mut self.auth_id_stroage.lock().unwrap();

        if let Some(username) = auth_id_storage.get_mut(&aid) {
            let mut user_info_storage = &mut self.user_info_storage.lock().unwrap();
            //* Verify retrieved username
            let user_info = user_info_storage.get_mut(username).expect("Not Found");

            let (alpha,beta,p,q) = ZKP::get_const();
            let zkp = ZKP{alpha,beta,p,q};

            //* Proceed verification.
            let verification = ZKP::verify(&zkp, &user_info.r1, &user_info.r2, &user_info.y1, &user_info.y2, &user_info.c, &s);

            if verification{
                let session_id = ZKP::gen_rand_str(12);
                Ok(Response::new(AuthenticationAnswerResponse{session_id}))
            }else{
                Err(Status::new(Code::PermissionDenied, format!("Permission Denied.")))
            }


        }else {
            Err(Status::new(Code::NotFound, format!("Invalid Auth Id.")))
        }
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