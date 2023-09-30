pub mod zkp_auth{ //* Make this module available.
    include!("./zkp_auth.rs");
}

use std::io::stdin;
use num_bigint::BigUint;
use zkp_chaum_pedersen::zkp_cp::ZKP;
use zkp_auth::{auth_service_client::AuthServiceClient, RegisterRequest};
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeRequest};

#[tokio::main] //* Async function
async fn main(){
    let mut buf:String = String::new();
    let addr_local = "http://127.0.0.1:50051".to_string();
    let (alpha,beta,p,q) = ZKP::get_const();
    let zkp = ZKP{
        alpha: alpha.clone(),
        beta: beta.clone(),
        p : p.clone(),
        q: q.clone()
    };

    let mut client = AuthServiceClient::connect(addr_local).await.expect("Cannot Connect to the server!");

    println!("💫💫 Successfully connected into a server.");
    println!("[Proceed Registration] Enter your name: ");
    stdin().read_line(&mut buf).expect("Cannot get user name");

    let username = buf.trim().to_string();
    buf.clear();

    println!("[Proceed Registration] Enter your password: ");
    stdin().read_line(&mut buf).expect("Cannot get user password");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes()); //* To byte.
    buf.clear();

    let y1 = ZKP::pow(&alpha, &password, &p);
    let y2 = ZKP::pow(&beta, &password, &p);

    let register_req = RegisterRequest{
        username: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be()
    };

    let _r_resp = client.register(register_req).await.expect("Cannot register");
    println!("{:?}",_r_resp);

    println!("👍 Successfully registered!");

    println!("\n\n[Verification] Enter your password: ");
    stdin().read_line(&mut buf).expect("Cannot get user password");
    let trial = BigUint::from_bytes_be(buf.trim().as_bytes()); //* To byte.
    buf.clear();

    //* Generate r1, r2.
    let k = ZKP::gen_rand(&q);
    let r1 = ZKP::pow(&alpha, &k, &p);
    let r2 = ZKP::pow(&beta, &k, &p);

    let challenge_req = AuthenticationChallengeRequest{
        username: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be()
    };

    let c_resp = client.create_authentication_challenge(challenge_req).await.expect("Cannot challange").into_inner();
    println!("{:?}",c_resp);

    let auth_id = c_resp.auth_id;
    let challenge = BigUint::from_bytes_be(&c_resp.c);

    //* Generate a solution based on secret password.
    let solution = zkp.solve(&k, &challenge, &trial);

    let verify_req = AuthenticationAnswerRequest{
        auth_id: auth_id.clone(),
        s: solution.to_bytes_be()
    };

    let v_resp = client.verify_authentication(verify_req).await.expect("Failed to verify").into_inner();
    println!("{:?}",v_resp);

    println!("Verified! Hello {}, your session id will be :{}", username, v_resp.session_id);

}