use std::collections::HashMap;

use crate::{
    cipher_suite::CipherSuite,
    group::{
        Commit, ContentType, GroupContext, GroupError, KeyType, MLSCiphertext,
        MLSCiphertextContent, MLSCiphertextContentAAD, MLSMessageContent, MLSPlaintext,
        MLSSenderData, MLSSenderDataAAD, PublicEpoch, Sender, VerifiedPlaintext,
    },
    signer::Signable,
    tree_kem::{node::LeafIndex, TreeKemPublic},
    AddProposal, Proposal,
};
use ferriscrypt::asym::ec_key::PublicKey;
use tls_codec::{Deserialize, Serialize};

use super::{epoch::Epoch, framing::Content, message_signature::MessageSigningContext};

pub(crate) enum SignaturePublicKeysContainer<'a> {
    RatchetTree(&'a TreeKemPublic),
    List(&'a HashMap<LeafIndex, PublicKey>),
}

pub fn verify_plaintext<F>(
    plaintext: MLSPlaintext,
    membership_key: &[u8],
    current_public_epoch: &PublicEpoch,
    context: &GroupContext,
    external_key_id_to_signing_key: F,
) -> Result<VerifiedPlaintext, GroupError>
where
    F: Fn(&[u8]) -> Option<PublicKey>,
{
    // Verify the membership tag if needed
    match plaintext.content.sender {
        Sender::Member(_) => {
            plaintext
                .membership_tag
                .as_ref()
                .map(|tag| {
                    tag.matches(
                        &plaintext,
                        context,
                        membership_key,
                        &current_public_epoch.cipher_suite,
                    )
                })
                .transpose()?
                .filter(|&matched| matched)
                .ok_or(GroupError::InvalidMembershipTag)?;
        }
        Sender::NewMember | Sender::Preconfigured(_) => {
            plaintext
                .membership_tag
                .is_none()
                .then(|| ())
                .ok_or(GroupError::InvalidMembershipTag)?;
        }
    }

    // Verify that the signature on the MLSPlaintext message verifies using the public key
    // from the credential stored at the leaf in the tree indicated by the sender field.
    verify_plaintext_signature(
        SignaturePublicKeysContainer::RatchetTree(&current_public_epoch.public_tree),
        context,
        plaintext,
        false,
        &external_key_id_to_signing_key,
        current_public_epoch.cipher_suite,
    )
}

pub(crate) fn decrypt_ciphertext(
    ciphertext: MLSCiphertext,
    msg_epoch: &mut Epoch,
) -> Result<VerifiedPlaintext, GroupError> {
    // Decrypt the sender data with the derived sender_key and sender_nonce from the message
    // epoch's key schedule
    let (sender_key, sender_nonce) = msg_epoch.get_sender_data_params(&ciphertext.ciphertext)?;

    let sender_data_aad = MLSSenderDataAAD {
        group_id: msg_epoch.context.group_id.clone(),
        epoch: msg_epoch.context.epoch,
        content_type: ciphertext.content_type,
    };

    let decrypted_sender = sender_key.decrypt_from_vec(
        &ciphertext.encrypted_sender_data,
        Some(&sender_data_aad.tls_serialize_detached()?),
        sender_nonce,
    )?;

    let sender_data = MLSSenderData::tls_deserialize(&mut &*decrypted_sender)?;
    if msg_epoch.self_index == sender_data.sender {
        return Err(GroupError::CantProcessMessageFromSelf);
    }

    // Grab a decryption key from the message epoch's key schedule
    let key_type = match &ciphertext.content_type {
        ContentType::Application => KeyType::Application,
        _ => KeyType::Handshake,
    };

    let decryption_key =
        msg_epoch.get_decryption_key(sender_data.sender, sender_data.generation, key_type)?;

    // Decrypt the content of the message using the grabbed key
    let decrypted_content = decryption_key.decrypt(
        &ciphertext.ciphertext,
        &MLSCiphertextContentAAD::from(&ciphertext).tls_serialize_detached()?,
        &sender_data.reuse_guard,
    )?;

    let ciphertext_content = MLSCiphertextContent::tls_deserialize(&mut &*decrypted_content)?;

    // Build the MLS plaintext object and process it
    let plaintext = MLSPlaintext {
        content: MLSMessageContent {
            group_id: ciphertext.group_id.clone(),
            epoch: ciphertext.epoch,
            sender: Sender::Member(sender_data.sender),
            authenticated_data: ciphertext.authenticated_data,
            content: ciphertext_content.content,
        },
        auth: ciphertext_content.auth,
        membership_tag: None, // Membership tag is always None for ciphertext messages
    };

    //Verify that the signature on the MLSPlaintext message verifies using the public key
    // from the credential stored at the leaf in the tree indicated by the sender field.
    verify_plaintext_signature(
        SignaturePublicKeysContainer::List(&msg_epoch.signature_public_keys),
        &msg_epoch.context,
        plaintext,
        true,
        |_| None,
        msg_epoch.cipher_suite,
    )
}

pub(crate) fn verify_plaintext_signature<F>(
    signature_keys_container: SignaturePublicKeysContainer,
    context: &GroupContext,
    plaintext: MLSPlaintext,
    from_ciphertext: bool,
    external_key_id_to_signing_key: F,
    cipher_suite: CipherSuite,
) -> Result<VerifiedPlaintext, GroupError>
where
    F: FnMut(&[u8]) -> Option<PublicKey>,
{
    let sender_public_key = public_key_for_sender(
        signature_keys_container,
        &plaintext.content.sender,
        &plaintext.content.content,
        external_key_id_to_signing_key,
        cipher_suite,
    )?;

    let context = MessageSigningContext {
        group_context: Some(context),
        encrypted: from_ciphertext,
    };

    plaintext.verify(&sender_public_key, &context)?;

    Ok(VerifiedPlaintext {
        encrypted: context.encrypted,
        plaintext,
    })
}

fn public_key_for_sender<F>(
    signature_keys_container: SignaturePublicKeysContainer,
    sender: &Sender,
    content: &Content,
    external_key_id_to_signing_key: F,
    cipher_suite: CipherSuite,
) -> Result<PublicKey, GroupError>
where
    F: FnMut(&[u8]) -> Option<PublicKey>,
{
    match sender {
        Sender::Member(leaf_index) => public_key_for_member(signature_keys_container, *leaf_index),
        Sender::Preconfigured(external_key_id) => {
            public_key_for_preconfigured(external_key_id, external_key_id_to_signing_key)
        }
        Sender::NewMember => public_key_for_new_member(content, cipher_suite),
    }
}

fn public_key_for_member(
    signature_keys_container: SignaturePublicKeysContainer,
    leaf_index: LeafIndex,
) -> Result<PublicKey, GroupError> {
    match signature_keys_container {
        SignaturePublicKeysContainer::RatchetTree(tree) => Ok(tree
            .get_leaf_node(leaf_index)?
            .signing_identity
            .public_key(tree.cipher_suite)?),
        SignaturePublicKeysContainer::List(list) => list
            .get(&leaf_index)
            .ok_or(GroupError::LeafNotFound(*leaf_index))
            .map(|pk| pk.clone()),
    }
}

fn public_key_for_preconfigured<F>(
    external_key_id: &[u8],
    mut external_key_id_to_signing_key: F,
) -> Result<PublicKey, GroupError>
where
    F: FnMut(&[u8]) -> Option<PublicKey>,
{
    external_key_id_to_signing_key(external_key_id)
        .ok_or(GroupError::UnknownSigningKeyForExternalSender)
}

fn public_key_for_new_member(
    content: &Content,
    cipher_suite: CipherSuite,
) -> Result<PublicKey, GroupError> {
    match content {
        Content::Commit(Commit {
            path: Some(path), ..
        }) => Ok(path.leaf_node.signing_identity.public_key(cipher_suite)?),
        Content::Proposal(Proposal::Add(AddProposal { key_package })) => Ok(key_package
            .leaf_node
            .signing_identity
            .public_key(cipher_suite)?),
        _ => Err(GroupError::NewMembersCanOnlyProposeAddingThemselves),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client_config::InMemoryPskStore,
        group::{
            framing::MLSCiphertext,
            membership_tag::MembershipTag,
            message_signature::MessageSigningContext,
            message_verifier::decrypt_ciphertext,
            padding::PaddingMode,
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_member, TEST_GROUP},
            CommitOptions, Content, ControlEncryptionMode, Group, GroupConfig, GroupError,
            InMemoryGroupConfig, MLSMessagePayload, MLSPlaintext, Sender, VerifiedPlaintext,
        },
        signer::{Signable, SignatureError},
        EpochRepository, ProtocolVersion,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::SecretKey;

    use crate::client_config::PassthroughCredentialValidator;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::verify_plaintext;

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;
    const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";

    fn make_plaintext(sender: Sender, epoch: u64) -> MLSPlaintext {
        MLSPlaintext::new(
            TEST_GROUP.to_vec(),
            epoch,
            sender,
            Content::Application(b"foo".to_vec()),
            vec![],
        )
    }

    fn add_membership_tag(message: &mut MLSPlaintext, group: &Group<InMemoryGroupConfig>) {
        message.membership_tag = Some(
            MembershipTag::create(
                message,
                &group.core.context,
                &group.key_schedule.membership_key,
                &group.core.cipher_suite,
            )
            .unwrap(),
        );
    }

    fn decrypt(
        ciphertext: MLSCiphertext,
        group: &mut Group<InMemoryGroupConfig>,
    ) -> Result<VerifiedPlaintext, GroupError> {
        let mut epoch = group
            .config
            .epoch_repo()
            .get(group.current_epoch())
            .unwrap()
            .unwrap();

        let res = decrypt_ciphertext(ciphertext, epoch.inner_mut());

        group
            .config
            .epoch_repo()
            .insert(group.current_epoch(), epoch)
            .unwrap();

        res
    }

    struct TestMember {
        signing_key: SecretKey,
        group: Group<InMemoryGroupConfig>,
    }

    impl TestMember {
        fn make_member_plaintext(&self) -> MLSPlaintext {
            make_plaintext(
                Sender::Member(self.group.private_tree.self_index),
                self.group.current_epoch(),
            )
        }

        fn sign(&self, message: &mut MLSPlaintext, encrypted: bool) {
            let signing_context = MessageSigningContext {
                group_context: Some(&self.group.core.context),
                encrypted,
            };

            message.sign(&self.signing_key, &signing_context).unwrap();
        }
    }

    struct TestEnv {
        alice: TestMember,
        bob: TestMember,
    }

    impl TestEnv {
        fn new() -> Self {
            let alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

            let mut alice = TestMember {
                signing_key: alice_group.signing_key,
                group: alice_group.group,
            };

            let (bob_key_pkg_gen, bob_signing_key) =
                test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

            let proposal = alice
                .group
                .add_proposal(bob_key_pkg_gen.key_package.clone())
                .unwrap();

            let secret_store = InMemoryPskStore::default();

            let commit_options = CommitOptions {
                prefer_path_update: false,
                extension_update: None,
                capabilities_update: None,
                encryption_mode: ControlEncryptionMode::Plaintext,
                ratchet_tree_extension: true,
            };

            let (commit_generation, welcome) = alice
                .group
                .commit_proposals(
                    vec![proposal],
                    commit_options,
                    &secret_store,
                    &alice.signing_key,
                    vec![],
                )
                .unwrap();

            let welcome = match welcome.unwrap().payload {
                MLSMessagePayload::Welcome(w) => w,
                _ => panic!("Expected Welcome message"),
            };

            alice
                .group
                .process_pending_commit(commit_generation, &secret_store)
                .unwrap();

            let bob_group = Group::from_welcome_message(
                TEST_PROTOCOL_VERSION,
                welcome,
                None,
                bob_key_pkg_gen,
                &secret_store,
                |_| InMemoryGroupConfig::default(),
                |_, _| true,
                PassthroughCredentialValidator::new(),
            )
            .unwrap();

            let bob = TestMember {
                signing_key: bob_signing_key,
                group: bob_group,
            };

            Self { alice, bob }
        }
    }

    #[test]
    fn valid_plaintext_is_verified() {
        let env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, false);
        add_membership_tag(&mut message, &env.alice.group);

        verify_plaintext(
            message,
            &env.bob.group.key_schedule.membership_key,
            &env.bob.group.current_public_epoch,
            env.bob.group.context(),
            |_| None,
        )
        .unwrap();
    }

    #[test]
    fn wire_format_is_signed() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, false);

        let message = env
            .alice
            .group
            .encrypt_plaintext(message, PaddingMode::None)
            .unwrap();

        let res = decrypt(message, &mut env.bob.group);

        assert_matches!(
            res,
            Err(GroupError::SignatureError(
                SignatureError::SignatureValidationFailed(_)
            ))
        );
    }

    #[test]
    fn valid_ciphertext_is_verified() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, true);

        let message = env
            .alice
            .group
            .encrypt_plaintext(message, PaddingMode::None)
            .unwrap();

        decrypt(message, &mut env.bob.group).unwrap();
    }

    #[test]
    fn plaintext_from_member_requires_membership_tag() {
        let env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, false);

        let res = verify_plaintext(
            message,
            &env.bob.group.key_schedule.membership_key,
            &env.bob.group.current_public_epoch,
            env.bob.group.context(),
            |_| None,
        );

        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn valid_proposal_from_new_member_is_verified() {
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(Sender::NewMember, test_group.group.current_epoch());
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: key_pkg_gen.key_package,
        }));

        let signing_context = MessageSigningContext {
            group_context: Some(test_group.group.context()),
            encrypted: false,
        };

        message.sign(&signer, &signing_context).unwrap();

        verify_plaintext(
            message,
            &test_group.group.key_schedule.membership_key,
            &test_group.group.current_public_epoch,
            test_group.group.context(),
            |_| None,
        )
        .unwrap();
    }

    #[test]
    fn proposal_from_new_member_must_not_have_membership_tag() {
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(Sender::NewMember, test_group.group.current_epoch());
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: key_pkg_gen.key_package,
        }));

        let signing_context = MessageSigningContext {
            group_context: Some(test_group.group.context()),
            encrypted: false,
        };

        message.sign(&signer, &signing_context).unwrap();
        add_membership_tag(&mut message, &test_group.group);

        let res = verify_plaintext(
            message,
            &test_group.group.key_schedule.membership_key,
            &test_group.group.current_public_epoch,
            test_group.group.context(),
            |_| None,
        );

        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn valid_proposal_from_preconfigured_external_is_verified() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let (_, ted_signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"ted");
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(
            Sender::Preconfigured(TED_EXTERNAL_KEY_ID.to_vec()),
            test_group.group.current_epoch(),
        );

        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: bob_key_pkg_gen.key_package,
        }));

        let signing_context = MessageSigningContext {
            group_context: None,
            encrypted: false,
        };

        message.sign(&ted_signer, &signing_context).unwrap();

        verify_plaintext(
            message,
            &test_group.group.key_schedule.membership_key,
            &test_group.group.current_public_epoch,
            test_group.group.context(),
            |external_id| {
                (external_id == TED_EXTERNAL_KEY_ID).then(|| ted_signer.to_public().unwrap())
            },
        )
        .unwrap();
    }

    #[test]
    fn proposal_from_preconfigured_external_must_not_have_membership_tag() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let (_, ted_signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"ted");
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(
            Sender::Preconfigured(TED_EXTERNAL_KEY_ID.to_vec()),
            test_group.group.current_epoch(),
        );
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: bob_key_pkg_gen.key_package,
        }));

        let signing_context = MessageSigningContext {
            group_context: None,
            encrypted: false,
        };

        message.sign(&ted_signer, &signing_context).unwrap();
        add_membership_tag(&mut message, &test_group.group);

        let res = verify_plaintext(
            message,
            &test_group.group.key_schedule.membership_key,
            &test_group.group.current_public_epoch,
            test_group.group.context(),
            |external_id| {
                (external_id == TED_EXTERNAL_KEY_ID).then(|| ted_signer.to_public().unwrap())
            },
        );

        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn ciphertext_from_self_fails_verification() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, true);

        let message = env
            .alice
            .group
            .encrypt_plaintext(message, PaddingMode::None)
            .unwrap();

        let res = decrypt(message, &mut env.alice.group);

        assert_matches!(res, Err(GroupError::CantProcessMessageFromSelf));
    }
}
