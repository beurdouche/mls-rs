use crate::ciphersuite::KemKeyPair;
use crate::key_package::KeyPackage;
use crate::tree_math::TreeMathError;
use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use crate::tree_math;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use std::hash::{Hash};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct Leaf {
    pub key_package: KeyPackage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct Parent {
    pub public_key: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub unmerged_leaves: Vec<LeafIndex>,
}

impl From<KemKeyPair> for Parent {
    fn from(kp: KemKeyPair) -> Self {
        Self {
            public_key: kp.public_key,
            parent_hash: vec![], // TODO: Parent hash calculations
            unmerged_leaves: vec![]
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub struct LeafIndex(pub (crate) usize);

impl TryFrom<NodeIndex> for LeafIndex {
    type Error = TreeMathError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value % 2 == 0 {
            Ok(Self(value / 2))
        } else {
            Err(TreeMathError::InvalidIndex)
        }
    }
}

impl Deref for LeafIndex {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&LeafIndex> for NodeIndex {
    fn from(leaf_index: &LeafIndex) -> Self {
        leaf_index.0 * 2
    }
}

impl From<LeafIndex> for NodeIndex {
    fn from(leaf_index: LeafIndex) -> Self {
        leaf_index.0 * 2
    }
}

impl LeafIndex {
    pub(crate) fn direct_path(&self, leaf_count: usize) -> Result<Vec<NodeIndex>, TreeMathError> {
        tree_math::direct_path(NodeIndex::from(self), leaf_count)
    }

    fn copath(&self, leaf_count: usize) -> Result<Vec<NodeIndex>, TreeMathError> {
        tree_math::copath(NodeIndex::from(self), leaf_count)
    }
}

pub (crate) type NodeIndex = usize;

#[derive(Error, Debug)]
pub enum NodeVecError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error("not a parent")]
    NotParentNode,
    #[error("not a leaf")]
    NotLeafNode,
    #[error("node index is out of bounds {0}")]
    InvalidNodeIndex(NodeIndex),
    #[error("unexpected empty node found")]
    UnexpectedEmptyNode
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) enum Node {
    Parent(Parent),
    Leaf(Leaf)
}

impl Node {
    pub fn get_public_key(&self) -> &Vec<u8> {
        match self {
            Node::Parent(p) => {
                &p.public_key
            },
            Node::Leaf(l) => {
                &l.key_package.hpke_init_key
            }
        }
    }
}

impl From<Parent> for Option<Node> {
    fn from(p: Parent) -> Self {
        Node::from(p).into()
    }
}

impl From<Leaf> for Option<Node> {
    fn from(l: Leaf) -> Self {
        Node::from(l).into()
    }
}

impl From<Parent> for Node {
    fn from(p: Parent) -> Self {
        Node::Parent(p)
    }
}

impl From<Leaf> for Node {
    fn from(l: Leaf) -> Self {
        Node::Leaf(l)
    }
}

impl From<KeyPackage> for Leaf {
    fn from(key_package: KeyPackage) -> Self {
        Leaf {
            key_package
        }
    }
}

impl From<KeyPackage> for Node {
    fn from(key_package: KeyPackage) -> Self {
        Node::Leaf(key_package.into())
    }
}

pub (crate) trait NodeTypeResolver {
    fn as_parent(&self) -> Result<&Parent, NodeVecError>;
    fn as_parent_mut(&mut self) -> Result<&mut Parent, NodeVecError>;
    fn as_leaf(&self) -> Result<&Leaf, NodeVecError>;
    fn as_leaf_mut(&mut self) -> Result<&mut Leaf, NodeVecError>;
    fn as_non_empty(&self) -> Result<&Node, NodeVecError>;
}

impl NodeTypeResolver for Option<Node> {
    fn as_parent(&self) -> Result<&Parent, NodeVecError> {
        self.as_ref().and_then(|n| match n {
            Node::Parent(p) => Some(p),
            Node::Leaf(_) => None
        }).ok_or(NodeVecError::NotParentNode)
    }

    fn as_parent_mut(&mut self) -> Result<&mut Parent, NodeVecError> {
        self.as_mut().and_then(|n| match n {
            Node::Parent(p) => Some(p),
            Node::Leaf(_) => None
        }).ok_or(NodeVecError::NotParentNode)
    }

    fn as_leaf(&self) -> Result<&Leaf, NodeVecError> {
        self.as_ref().and_then(|n| match n {
            Node::Parent(_) => None,
            Node::Leaf(l) => Some(l)
        }).ok_or(NodeVecError::NotLeafNode)
    }

    fn as_leaf_mut(&mut self) -> Result<&mut Leaf, NodeVecError> {
        self.as_mut().and_then(|n| match n {
            Node::Parent(_) => None,
            Node::Leaf(l) => Some(l)
        }).ok_or(NodeVecError::NotLeafNode)
    }

    fn as_non_empty(&self) -> Result<&Node, NodeVecError> {
        self.as_ref()
            .ok_or(NodeVecError::UnexpectedEmptyNode)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct NodeVec(Vec<Option<Node>>);

impl From<Vec<Option<Node>>> for NodeVec {
    fn from(x: Vec<Option<Node>>) -> Self {
        NodeVec(x)
    }
}

impl Deref for NodeVec {
    type Target = Vec<Option<Node>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NodeVec {
    pub fn leaf_count(&self) -> usize {
        self.len() / 2 + 1
    }

    pub fn empty_leaves(&mut self) -> impl Iterator<Item=(LeafIndex, &mut Option<Node>)> + '_ {
        // List of empty leaves from left to right
        self.iter_mut()
            .enumerate()
            .step_by(2)
            .filter(|(_, n)| n.is_none())
            .map(|(i,n)| (LeafIndex(i / 2), n))
    }

    pub fn non_empty_leaves(&self) -> impl Iterator<Item=(LeafIndex, &Leaf)> + '_ {
        self.iter()
            .enumerate()
            .step_by(2)
            .map(|(i, n)| (LeafIndex(i / 2), n))
            .filter_map(|(i, n)| n.as_leaf().ok().map(|l| (i, l)))
    }

    pub fn direct_path(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
        // Direct path from leaf to root
        index.direct_path(self.len() / 2 + 1)
    }

    pub fn copath(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
        // Co path from leaf to root
        index.copath(self.len() / 2 + 1)
    }

    pub fn get_parent_node_mut(&mut self, node_index: NodeIndex) -> Result<&mut Parent, NodeVecError> {
        self.get_mut(node_index)
            .ok_or(NodeVecError::InvalidNodeIndex(node_index))
            .and_then(|n| n.as_parent_mut())
    }

    pub fn get_leaf_node_mut(&mut self, node_index: NodeIndex) -> Result<&mut Leaf, NodeVecError> {
        self.get_mut(node_index)
            .ok_or(NodeVecError::InvalidNodeIndex(node_index))
            .and_then(|n| n.as_leaf_mut())
    }

    pub fn get_leaf_node(&self, leaf_index: LeafIndex) -> Result<&Leaf, NodeVecError> {
        let node_index = NodeIndex::from(leaf_index);
        self.get(node_index)
            .ok_or(NodeVecError::InvalidNodeIndex(node_index))
            .and_then(|n| n.as_leaf())
    }

    pub fn get_or_fill_parent_node(
        &mut self,
        node_index: NodeIndex,
        public_key: &[u8],
    ) -> Result<&mut Parent, NodeVecError> {
        self.get_mut(node_index)
            .ok_or(NodeVecError::InvalidNodeIndex(node_index))
            .and_then(|n| {
                if n.is_none() {
                    *n = Parent {
                        public_key: public_key.to_vec(),
                        parent_hash: vec![], // TODO Parent hash
                        unmerged_leaves: vec![]
                    }.into();
                }
                n.as_parent_mut()
            })
    }

    pub fn get_resolution_index(&self, index: NodeIndex) -> Result<Vec<NodeIndex>, NodeVecError> {
        if let Some(node) = self.get(index) {
            match node {
                None => { // This node is blank
                    if LeafIndex::try_from(index).is_ok() { // Node is a leaf {
                        Ok(Vec::new()) // Resolution of a blank leaf node is empty list
                    } else {
                        // Resolution of a blank intermediate is is the result of concatenating the
                        // resolution of its left and right children
                        Ok([
                            self.get_resolution_index(tree_math::left(index)?)?,
                            self.get_resolution_index(tree_math::right(index,
                                                                 self.len() / 2 + 1)?)?
                        ].concat())
                    }
                }
                Some(node) => {
                    // Resolution of a non blank node comprises the node itself + unmerged leaves
                    match node {
                        Node::Parent(parent) => {
                            let mut ret = vec![index];
                            ret.extend(
                                parent.unmerged_leaves.iter()
                                    .map(NodeIndex::from)
                            );
                            Ok(ret)
                        }
                        Node::Leaf(_) => {
                            Ok(vec![index])
                        }
                    }
                }
            }
        } else {
            Err(TreeMathError::InvalidIndex.into())
        }
    }

    pub fn get_resolution(&self, node_index: NodeIndex, excluding: &[NodeIndex]) -> Result<Vec<&Node>, NodeVecError> {
        self.get_resolution_index(node_index)?
            .iter()
            .filter(|i|!excluding.contains(i))
            .map(|&i| {
                self.get(i)
                    .ok_or(NodeVecError::InvalidNodeIndex(i))
                    .and_then(|n| n.as_non_empty())
            })

            .collect()
    }

    pub fn direct_path_copath_resolution(&self, index: LeafIndex, excluding: &[LeafIndex])
        -> Result<Vec<(NodeIndex, Vec<&Node>)>, NodeVecError> {
        let excluding = excluding
            .iter()
            .map(NodeIndex::from)
            .collect::<Vec<NodeIndex>>();

        self.direct_path(index)?
            .iter()
            .zip(self.copath(index)?)
            .map(|(&dp, cp)| self.get_resolution(cp, &excluding)
                .map(|r| (dp, r)) )
            .collect()
    }
}

#[cfg(test)]
mod test {
    use crate::tree_node::{NodeVec, Node, Parent, LeafIndex, NodeTypeResolver, NodeIndex};
    use crate::tree_node::Leaf;
    use crate::key_package::{KeyPackage};
    use crate::protocol_version::ProtocolVersion;
    use crate::ciphersuite::test_util::MockCipherSuite;
    use crate::credential::{BasicCredential, CredentialConvertable};
    use crate::signature::SignatureSchemeId;
    use crate::extension::ExtensionList;

    fn get_mock_cipher_suite() -> MockCipherSuite {
        let mut cipher_suite = MockCipherSuite::new();
        cipher_suite.expect_clone().returning_st(move || get_mock_cipher_suite());
        cipher_suite.expect_get_id().returning_st(move || 42);
        cipher_suite
    }

    fn get_test_key_package(id: Vec<u8>) -> KeyPackage {
        KeyPackage {
            version: ProtocolVersion::Test,
            cipher_suite: get_mock_cipher_suite(),
            hpke_init_key: vec![],
            credential: BasicCredential {
                signature_key: vec![],
                identity: id,
                signature_scheme: SignatureSchemeId::Test
            }.to_credential(),
            extensions: ExtensionList(vec![]),
            signature: vec![]
        }
    }

    fn get_test_node_vec() -> NodeVec {
        let nodes = [
            Leaf {
                key_package: get_test_key_package(b"A".to_vec()),
            }.into(),
            None,
            None,
            None,
            Leaf {
                key_package: get_test_key_package(b"C".to_vec()),
            }.into(),
            Parent {
                public_key: b"CD".to_vec(),
                parent_hash: vec![],
                unmerged_leaves: vec![LeafIndex(2)]
            }.into(),
            Leaf {
                key_package: get_test_key_package(b"D".to_vec()),
            }.into()
        ];

        NodeVec::from(nodes.to_vec())
    }

    #[test]
    fn node_key_getters() {
        let test_node_parent: Node = Parent {
            public_key: b"pub".to_vec(),
            parent_hash: vec![],
            unmerged_leaves: vec![]
        }.into();

        let mut test_key_package = get_test_key_package(b"B".to_vec());
        test_key_package.hpke_init_key = b"pub_leaf".to_vec();

        let test_node_leaf: Node = Leaf {
            key_package: test_key_package,
        }.into();

        assert_eq!(test_node_parent.get_public_key(), &b"pub".to_vec());
        assert_eq!(test_node_leaf.get_public_key(), &b"pub_leaf".to_vec());
    }

    #[test]
    fn test_empty_leaves() {
        let mut test_vec = get_test_node_vec();
        let mut test_vec_clone = get_test_node_vec();
        let empty_leaves: Vec<(LeafIndex, &mut Option<Node>)> = test_vec.empty_leaves().collect();
        assert_eq!([(LeafIndex(1), &mut test_vec_clone[2])].as_ref(), empty_leaves.as_slice());
    }

    #[test]
    fn test_direct_path() {
        let test_vec = get_test_node_vec();
        // Tree math is already tested in that module, just ensure equality
        let expected = crate::tree_math::direct_path(0, 4).unwrap();
        let actual = test_vec.direct_path(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_copath() {
        let test_vec = get_test_node_vec();
        // Tree math is already tested in that module, just ensure equality
        let expected = crate::tree_math::copath(0, 4).unwrap();
        let actual = test_vec.copath(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_get_parent_node() {
        let mut test_vec = get_test_node_vec();

        // If the node is a leaf it should fail
        assert_eq!(test_vec.get_parent_node_mut(0).is_err(), true);

        // If the node index is out of range it should fail
        assert_eq!(test_vec.get_parent_node_mut(test_vec.len()).is_err(), true);

        // Otherwise it should succeed
        let mut expected = Parent {
            public_key: b"CD".to_vec(),
            parent_hash: vec![],
            unmerged_leaves: vec![LeafIndex(2)]
        };

        assert_eq!(test_vec.get_parent_node_mut(5).unwrap(), &mut expected);
    }

    #[test]
    fn test_get_resolution() {
        let test_vec = get_test_node_vec();

        let resolution_node_5 = test_vec.get_resolution(5, &vec![])
            .unwrap();
        let resolution_node_2 = test_vec.get_resolution(2, &vec![])
            .unwrap();
        let resolution_node_3 = test_vec.get_resolution(3, &vec![])
            .unwrap();

        let expected_5: Vec<Node> = [
            Parent {
                public_key: b"CD".to_vec(),
                parent_hash: vec![],
                unmerged_leaves: vec![LeafIndex(2)]
            }.into(),
            Leaf {
                key_package: get_test_key_package(b"C".to_vec()),
            }.into()
        ].to_vec();

        let expected_2: Vec<&Node> = [].to_vec();

        let expected_3: Vec<Node> = [
            Leaf {
                key_package: get_test_key_package(b"A".to_vec()),
            }.into(),
            Parent {
                public_key: b"CD".to_vec(),
                parent_hash: vec![],
                unmerged_leaves: vec![LeafIndex(2)]
            }.into(),
            Leaf {
                key_package: get_test_key_package(b"C".to_vec()),
            }.into()
        ].to_vec();

        assert_eq!(resolution_node_5, expected_5.iter().map(|n| n).collect::<Vec<&Node>>());
        assert_eq!(resolution_node_2, expected_2);
        assert_eq!(resolution_node_3, expected_3.iter().map(|n| n).collect::<Vec<&Node>>());
    }

    #[test]
    fn test_resolution_filter() {
        let test_vec = get_test_node_vec();

        let resolution_node_5 = test_vec.get_resolution(5, &vec![4])
            .unwrap();

        let expected_5: Vec<Node> = [
            Parent {
                public_key: b"CD".to_vec(),
                parent_hash: vec![],
                unmerged_leaves: vec![LeafIndex(2)]
            }.into()
        ].to_vec();

        assert_eq!(resolution_node_5, expected_5.iter().map(|n| n).collect::<Vec<&Node>>());
    }

    #[test]
    fn test_copath_resolution() {
        let test_vec = get_test_node_vec();

        let expected: Vec<(NodeIndex, Vec<Node>)> = [(1,[].to_vec()),
            (3, [
                Parent {
                    public_key: b"CD".to_vec(),
                    parent_hash: vec![],
                    unmerged_leaves: vec![LeafIndex(2)]
                }.into(),
                Leaf {
                    key_package: get_test_key_package(b"C".to_vec()),
                }.into()
            ].to_vec())
        ].to_vec();

        let copath_resolution = test_vec
            .direct_path_copath_resolution(LeafIndex(0), &vec![])
            .unwrap();

        let expected: Vec<(NodeIndex, Vec<&Node>)> = expected
            .iter()
            .map(|(i,n)| (*i, n.iter().map(|n| n).collect())).collect();

        assert_eq!(expected, copath_resolution)
    }

    #[test]
    fn test_copath_resolution_filter() {
        let test_vec = get_test_node_vec();

        let expected: Vec<(NodeIndex, Vec<Node>)> = [(1,[].to_vec()),
            (3, [
                Parent {
                    public_key: b"CD".to_vec(),
                    parent_hash: vec![],
                    unmerged_leaves: vec![LeafIndex(2)]
                }.into(),
            ].to_vec())
        ].to_vec();

        let copath_resolution = test_vec
            .direct_path_copath_resolution(LeafIndex(0), &vec![LeafIndex(2)])
            .unwrap();

        let expected: Vec<(NodeIndex, Vec<&Node>)> = expected
            .iter()
            .map(|(i,n)| (*i, n.iter().map(|n| n).collect())).collect();

        assert_eq!(expected, copath_resolution)
    }

    #[test]
    fn test_get_or_fill_existing() {
        let mut test_vec = get_test_node_vec();
        let mut test_vec2 = test_vec.clone();

        let expected = test_vec[5].as_parent_mut().unwrap();
        let actual = test_vec2.get_or_fill_parent_node(5,
                                                      &vec![]).unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_get_or_fill_empty() {
        let mut test_vec = get_test_node_vec();

        let mut expected = Parent {
            public_key: vec![0u8;4],
            parent_hash: vec![],
            unmerged_leaves: vec![]
        };

        let actual = test_vec.get_or_fill_parent_node(1,
                                                       &vec![0u8;4]).unwrap();

        assert_eq!(actual, &mut expected);
    }
}