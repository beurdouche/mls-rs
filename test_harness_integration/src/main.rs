//! This is the OpenMLS client for the interop harness as described here:
//! <https://github.com/mlswg/mls-implementations/tree/master/interop>
//!
//! It is based on the Mock client written by Richard Barnes.

use aws_mls::cipher_suite::{CipherSuite, SignaturePublicKey};
use aws_mls::client::Client;
use aws_mls::client_config::{InMemoryClientConfig, Preferences, ONE_YEAR_IN_SECONDS};
use aws_mls::credential::Credential;
use aws_mls::extension::ExtensionList;
use aws_mls::message::ProcessedMessagePayload;
use aws_mls::session::Session;
use aws_mls::signing_identity::SigningIdentity;
use aws_mls::ProtocolVersion;

use clap::Parser;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::sync::Mutex;
use tonic::{transport::Server, Code::Aborted, Request, Response, Status};

use mls_client::mls_client_server::{MlsClient, MlsClientServer};
// TODO(RLB) Convert this back to more specific `use` directives
use mls_client::*;

fn abort<T: std::fmt::Debug>(e: T) -> Status {
    Status::new(Aborted, format!("Aborted with error {e:?}"))
}

pub mod mls_client {
    tonic::include_proto!("mls_client");
}

const IMPLEMENTATION_NAME: &str = "AWS MLS";
const TEST_VECTOR: [u8; 4] = [0, 1, 2, 3];

impl TryFrom<i32> for TestVectorType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TestVectorType::TreeMath),
            1 => Ok(TestVectorType::Encryption),
            2 => Ok(TestVectorType::KeySchedule),
            3 => Ok(TestVectorType::Transcript),
            4 => Ok(TestVectorType::Treekem),
            5 => Ok(TestVectorType::Messages),
            _ => Err(()),
        }
    }
}

#[derive(Default)]
pub struct MlsClientImpl {
    clients: Mutex<Vec<Client<InMemoryClientConfig>>>,
    sessions: Mutex<Vec<Session<InMemoryClientConfig>>>,
}

impl MlsClientImpl {
    const FIXED_STATE_ID: u32 = 43;
    // TODO(RLB): Figure out how to make these work with non-fixed values
    fn new_state_id(&self) -> u32 {
        MlsClientImpl::FIXED_STATE_ID
    }
    fn known_state_id(&self, id: u32) -> bool {
        id == MlsClientImpl::FIXED_STATE_ID
    }
}

#[tonic::async_trait]
impl MlsClient for MlsClientImpl {
    async fn name(&self, _request: Request<NameRequest>) -> Result<Response<NameResponse>, Status> {
        let response = NameResponse {
            name: IMPLEMENTATION_NAME.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn supported_ciphersuites(
        &self,
        _request: tonic::Request<SupportedCiphersuitesRequest>,
    ) -> Result<tonic::Response<SupportedCiphersuitesResponse>, tonic::Status> {
        let response = SupportedCiphersuitesResponse {
            ciphersuites: CipherSuite::all().map(|cs| cs as u32).collect(),
        };

        Ok(Response::new(response))
    }

    /* Taken verbatim from the mock client. It will likely be deleted. */
    async fn generate_test_vector(
        &self,
        request: tonic::Request<GenerateTestVectorRequest>,
    ) -> Result<tonic::Response<GenerateTestVectorResponse>, tonic::Status> {
        println!("Got GenerateTestVector request");

        let obj = request.get_ref();
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => "Tree math",
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        let response = GenerateTestVectorResponse {
            test_vector: TEST_VECTOR.to_vec(),
        };

        Ok(Response::new(response))
    }

    async fn verify_test_vector(
        &self,
        request: tonic::Request<VerifyTestVectorRequest>,
    ) -> Result<tonic::Response<VerifyTestVectorResponse>, tonic::Status> {
        println!("Got VerifyTestVector request");

        let obj = request.get_ref();
        let type_msg = match TestVectorType::try_from(obj.test_vector_type) {
            Ok(TestVectorType::TreeMath) => "Tree math",
            Ok(TestVectorType::Encryption) => "Encryption",
            Ok(TestVectorType::KeySchedule) => "Key Schedule",
            Ok(TestVectorType::Transcript) => "Transcript",
            Ok(TestVectorType::Treekem) => "TreeKEM",
            Ok(TestVectorType::Messages) => "Messages",
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid test vector type",
                ));
            }
        };
        println!("{} test vector request", type_msg);

        if obj.test_vector != TEST_VECTOR {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid test vector",
            ));
        }

        Ok(Response::new(VerifyTestVectorResponse::default()))
    }

    async fn create_group(
        &self,
        request: tonic::Request<CreateGroupRequest>,
    ) -> Result<tonic::Response<CreateGroupResponse>, tonic::Status> {
        let request_ref = request.get_ref();

        let cipher_suite = CipherSuite::from_raw(request_ref.cipher_suite as u16)
            .ok_or_else(|| Status::new(Aborted, "ciphersuite not supported"))?;

        let secret_key = cipher_suite.generate_signing_key().map_err(abort)?;
        let credential = Credential::Basic(b"creator".to_vec());
        let signature_key = SignaturePublicKey::try_from(&secret_key).map_err(abort)?;

        let creator = InMemoryClientConfig::default()
            .with_signing_identity(SigningIdentity::new(credential, signature_key), secret_key)
            .with_preferences(Preferences::default().with_ratchet_tree_extension(true))
            .with_lifetime_duration(ONE_YEAR_IN_SECONDS)
            .build_client();

        let session = creator
            .create_session(
                ProtocolVersion::Mls10,
                cipher_suite,
                request_ref.group_id.clone(),
                ExtensionList::default(),
            )
            .map_err(abort)?;

        let mut sessions = self.sessions.lock().unwrap();
        sessions.push(session);

        Ok(Response::new(CreateGroupResponse {
            state_id: sessions.len() as u32,
        }))
    }

    async fn create_key_package(
        &self,
        request: tonic::Request<CreateKeyPackageRequest>,
    ) -> Result<tonic::Response<CreateKeyPackageResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut clients = self.clients.lock().unwrap();
        let cipher_suite = CipherSuite::from_raw(request_ref.cipher_suite as u16).unwrap();

        let secret_key = cipher_suite.generate_signing_key().map_err(abort)?;
        let credential = Credential::Basic(format!("alice{}", clients.len()).into_bytes());
        let signature_key = SignaturePublicKey::try_from(&secret_key).map_err(abort)?;

        let client = InMemoryClientConfig::default()
            .with_signing_identity(SigningIdentity::new(credential, signature_key), secret_key)
            .with_preferences(Preferences::default().with_ratchet_tree_extension(true))
            .with_lifetime_duration(ONE_YEAR_IN_SECONDS)
            .build_client();

        let key_package = client
            .gen_key_package(ProtocolVersion::Mls10, cipher_suite)
            .map_err(abort)?;

        clients.push(client);

        let resp = CreateKeyPackageResponse {
            transaction_id: clients.len() as u32,
            key_package: key_package.key_package.to_vec().map_err(abort)?,
        };

        Ok(Response::new(resp))
    }

    async fn join_group(
        &self,
        request: tonic::Request<JoinGroupRequest>,
    ) -> Result<tonic::Response<JoinGroupResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let clients = self.clients.lock().unwrap();
        let client_index = request_ref.transaction_id as usize - 1;

        let session = clients[client_index]
            .join_session(None, None, &request_ref.welcome)
            .map_err(abort)?;

        let mut sessions = self.sessions.lock().unwrap();
        sessions.push(session);

        Ok(Response::new(JoinGroupResponse {
            state_id: sessions.len() as u32,
        }))
    }

    async fn external_join(
        &self,
        request: tonic::Request<ExternalJoinRequest>,
    ) -> Result<tonic::Response<ExternalJoinResponse>, tonic::Status> {
        let obj = request.get_ref();
        let public_group_state = String::from("publicGroupState");
        let public_group_state_in = String::from_utf8(obj.public_group_state.clone()).unwrap();
        if public_group_state != public_group_state_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid public_group_state",
            ));
        }

        let resp = ExternalJoinResponse {
            state_id: self.new_state_id(),
            commit: String::from("commit").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn public_group_state(
        &self,
        request: tonic::Request<PublicGroupStateRequest>,
    ) -> Result<tonic::Response<PublicGroupStateResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let resp = PublicGroupStateResponse {
            public_group_state: String::from("publicGroupState").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn state_auth(
        &self,
        request: tonic::Request<StateAuthRequest>,
    ) -> Result<tonic::Response<StateAuthResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Invalid state ID: {}", obj.state_id),
            ));
        }

        let resp = StateAuthResponse {
            state_auth_secret: String::from("stateAuthSecret").into_bytes(),
        };

        Ok(Response::new(resp)) // TODO
    }

    async fn export(
        &self,
        request: tonic::Request<ExportRequest>,
    ) -> Result<tonic::Response<ExportResponse>, tonic::Status> {
        let obj = request.get_ref();
        if self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                format!("Invalid state ID: {}", obj.state_id),
            ));
        }

        let resp = ExportResponse {
            exported_secret: String::from("exportedSecret").into_bytes(),
        };

        Ok(Response::new(resp))
    }

    async fn protect(
        &self,
        request: tonic::Request<ProtectRequest>,
    ) -> Result<tonic::Response<ProtectResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut sessions = self.sessions.lock().unwrap();

        let ciphertext = sessions
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .encrypt_application_data(&request_ref.application_data, vec![])
            .map_err(abort)?;

        Ok(Response::new(ProtectResponse { ciphertext }))
    }

    async fn unprotect(
        &self,
        request: tonic::Request<UnprotectRequest>,
    ) -> Result<tonic::Response<UnprotectResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut sessions = self.sessions.lock().unwrap();

        let message = sessions
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .process_incoming_bytes(&request_ref.ciphertext)
            .map_err(abort)?;

        let application_data = match message.message {
            ProcessedMessagePayload::Application(plaintext) => plaintext,
            _ => {
                return Err(Status::new(
                    Aborted,
                    "message type is not application data.",
                ))
            }
        };

        Ok(Response::new(UnprotectResponse { application_data }))
    }

    async fn store_psk(
        &self,
        _request: tonic::Request<StorePskRequest>,
    ) -> Result<tonic::Response<StorePskResponse>, tonic::Status> {
        Ok(Response::new(StorePskResponse::default())) // TODO
    }

    async fn add_proposal(
        &self,
        request: tonic::Request<AddProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut sessions = self.sessions.lock().unwrap();

        let proposal_packet = sessions
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .propose_add(&request_ref.key_package, vec![])
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn update_proposal(
        &self,
        request: tonic::Request<UpdateProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut sessions = self.sessions.lock().unwrap();

        let proposal_packet = sessions
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .propose_update(vec![])
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn remove_proposal(
        &self,
        request: tonic::Request<RemoveProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let mut sessions = self.sessions.lock().unwrap();

        let proposal_packet = sessions
            .get_mut(request_ref.state_id as usize - 1)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .propose_remove(request_ref.removed_leaf_index, vec![])
            .map_err(abort)?;

        Ok(Response::new(ProposalResponse {
            proposal: proposal_packet,
        }))
    }

    async fn psk_proposal(
        &self,
        _request: tonic::Request<PskProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn re_init_proposal(
        &self,
        _request: tonic::Request<ReInitProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn app_ack_proposal(
        &self,
        _request: tonic::Request<AppAckProposalRequest>,
    ) -> Result<tonic::Response<ProposalResponse>, tonic::Status> {
        Ok(Response::new(ProposalResponse::default())) // TODO
    }

    async fn commit(
        &self,
        request: tonic::Request<CommitRequest>,
    ) -> Result<tonic::Response<CommitResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let session_index = request_ref.state_id as usize - 1;
        let mut sessions = self.sessions.lock().unwrap();

        for proposal in &request_ref.by_reference {
            sessions
                .get_mut(session_index)
                .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
                .process_incoming_bytes(proposal)
                .map_err(abort)?;
        }

        // TODO: handle by value

        let commit = sessions
            .get_mut(session_index)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .commit(vec![], vec![])
            .map_err(abort)?;

        let resp = CommitResponse {
            commit: commit.commit_packet,
            welcome: commit.welcome_packet.unwrap_or_default(),
        };

        Ok(Response::new(resp))
    }

    async fn handle_commit(
        &self,
        request: tonic::Request<HandleCommitRequest>,
    ) -> Result<tonic::Response<HandleCommitResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let session_index = request_ref.state_id as usize - 1;
        let mut sessions = self.sessions.lock().unwrap();

        for proposal in &request_ref.proposal {
            sessions
                .get_mut(session_index)
                .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
                .process_incoming_bytes(proposal)
                .map_err(abort)?;
        }

        let message = sessions
            .get_mut(session_index)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .process_incoming_bytes(&request_ref.commit)
            .map_err(abort)?;

        let state_update = match message.message {
            ProcessedMessagePayload::Commit(state_update) => state_update,
            _ => return Err(Status::new(Aborted, "message not a commit.")),
        };

        let added: Vec<Vec<u8>> = state_update
            .added
            .iter()
            .map(|leaf_node_ref| (**leaf_node_ref).to_be_bytes().to_vec())
            .collect();

        let removed = vec![]; // TODO what to return here??

        Ok(Response::new(HandleCommitResponse {
            state_id: request_ref.state_id,
            added,
            removed,
        }))
    }

    async fn handle_pending_commit(
        &self,
        request: tonic::Request<HandlePendingCommitRequest>,
    ) -> Result<tonic::Response<HandlePendingCommitResponse>, tonic::Status> {
        let request_ref = request.get_ref();
        let session_index = request_ref.state_id as usize - 1;
        let mut sessions = self.sessions.lock().unwrap();

        let state_update = sessions
            .get_mut(session_index)
            .ok_or_else(|| Status::new(Aborted, "no session with such index."))?
            .apply_pending_commit()
            .map_err(abort)?;

        let added: Vec<Vec<u8>> = state_update
            .added
            .iter()
            .map(|leaf_node_ref| (**leaf_node_ref).to_be_bytes().to_vec())
            .collect();

        let removed = vec![]; // TODO what to return here??

        Ok(Response::new(HandlePendingCommitResponse {
            state_id: request_ref.state_id,
            added,
            removed,
        }))
    }

    async fn handle_external_commit(
        &self,
        request: tonic::Request<HandleExternalCommitRequest>,
    ) -> Result<tonic::Response<HandleExternalCommitResponse>, tonic::Status> {
        let obj = request.get_ref();
        if !self.known_state_id(obj.state_id) {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid state ID",
            ));
        }

        let obj = request.get_ref();
        let commit = String::from("commit");
        let commit_in = String::from_utf8(obj.commit.clone()).unwrap();
        if commit != commit_in {
            return Err(tonic::Status::new(
                tonic::Code::InvalidArgument,
                "Invalid commit",
            ));
        }

        let resp = HandleExternalCommitResponse {
            state_id: self.new_state_id(),
        };

        Ok(Response::new(resp)) // TODO
    }
}

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = "::1")]
    host: IpAddr,

    #[clap(short, long, default_value = "50003")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    let mls_client_impl = MlsClientImpl::default();

    Server::builder()
        .add_service(MlsClientServer::new(mls_client_impl))
        .serve((opts.host, opts.port).into())
        .await?;

    Ok(())
}