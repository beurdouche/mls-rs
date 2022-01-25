use super::*;
use crate::hash_reference::HashReference;

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ProposalRef(HashReference);

impl Deref for ProposalRef {
    type Target = HashReference;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProposalRef {
    pub fn from_plaintext(
        cipher_suite: CipherSuite,
        plaintext: &MLSPlaintext,
    ) -> Result<Self, ProposalCacheError> {
        Ok(ProposalRef(HashReference::from_value(
            &plaintext.tls_serialize_detached()?,
            cipher_suite,
        )?))
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    pub fn plaintext_from_proposal(proposal: Proposal, sender: KeyPackageRef) -> MLSPlaintext {
        MLSPlaintext {
            group_id: b"test_group".to_vec(),
            epoch: 0,
            sender: Sender::Member(sender),
            authenticated_data: vec![],
            content: Content::Proposal(proposal),
            signature: MessageSignature::from(SecureRng::gen(128).unwrap()),
            confirmation_tag: None,
            membership_tag: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::test_util::plaintext_from_proposal;
    use super::*;
    use crate::tree_kem::test::get_test_key_package;

    fn get_test_extension_list() -> ExtensionList {
        let test_extension = RequiredCapabilitiesExt {
            extensions: vec![42],
            proposals: Default::default(),
        };

        let mut extension_list = ExtensionList::new();
        extension_list.set_extension(test_extension).unwrap();

        extension_list
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    #[allow(dead_code)]
    fn generate_proposal_test_cases() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in CipherSuite::all() {
            let mut sender = [0u8; 16];
            SecureRng::fill(&mut sender).unwrap();

            let add = plaintext_from_proposal(
                Proposal::Add(AddProposal {
                    key_package: get_test_key_package(cipher_suite, SecureRng::gen(16).unwrap())
                        .key_package
                        .into(),
                }),
                sender.into(),
            );

            let update = plaintext_from_proposal(
                Proposal::Update(UpdateProposal {
                    key_package: get_test_key_package(cipher_suite, SecureRng::gen(16).unwrap())
                        .key_package
                        .into(),
                }),
                sender.into(),
            );

            let mut key_package_ref = [0u8; 16];
            SecureRng::fill(&mut key_package_ref).unwrap();

            let remove = plaintext_from_proposal(
                Proposal::Remove(RemoveProposal {
                    to_remove: key_package_ref.into(),
                }),
                sender.into(),
            );

            let group_context_ext = plaintext_from_proposal(
                Proposal::GroupContextExtensions(get_test_extension_list()),
                sender.into(),
            );

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: add.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_plaintext(cipher_suite, &add)
                    .unwrap()
                    .to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: update.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_plaintext(cipher_suite, &update)
                    .unwrap()
                    .to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: remove.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_plaintext(cipher_suite, &remove)
                    .unwrap()
                    .to_vec(),
            });

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                input: group_context_ext.tls_serialize_detached().unwrap(),
                output: ProposalRef::from_plaintext(cipher_suite, &group_context_ext)
                    .unwrap()
                    .to_vec(),
            });
        }

        /*
        std::fs::write(
            "path/to/test_data/proposal_ref.json",
            serde_json::to_vec_pretty(&test_cases).unwrap(),
        )
        .unwrap();
        */

        test_cases
    }

    #[test]
    fn test_proposal_ref() {
        let test_cases: Vec<TestCase> =
            serde_json::from_slice(include_bytes!("../../test_data/proposal_ref.json")).unwrap();

        for one_case in test_cases {
            let proposal = MLSPlaintext::tls_deserialize(&mut one_case.input.as_slice()).unwrap();

            let proposal_ref = ProposalRef::from_plaintext(
                CipherSuite::from_raw(one_case.cipher_suite).unwrap(),
                &proposal,
            )
            .unwrap();

            let expected_out = ProposalRef(HashReference::from(
                <[u8; 16]>::try_from(one_case.output).unwrap(),
            ));

            assert_eq!(expected_out, proposal_ref);
        }
    }
}
