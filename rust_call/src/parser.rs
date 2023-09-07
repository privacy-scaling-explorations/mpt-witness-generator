use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Tag for an AccountField in RwTable
#[derive(Clone, Copy, Debug, EnumIter, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountFieldTag {
    /// Nonce field
    Nonce = 1,
    /// Balance field
    Balance,
    /// CodeHash field
    CodeHash,
    /// NonExisting field
    NonExisting,
}

/// The types of proofs in the MPT table
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MPTProofType {
    /// Disabled
    Disabled,
    /// Nonce updated
    NonceChanged = AccountFieldTag::Nonce as isize,
    /// Balance updated
    BalanceChanged = AccountFieldTag::Balance as isize,
    /// Code hash updated
    CodeHashChanged = AccountFieldTag::CodeHash as isize,
    /// Account destroyed
    AccountDestructed,
    /// Account does not exist
    AccountDoesNotExist,
    /// Storage updated
    StorageChanged,
    /// Storage does not exist
    StorageDoesNotExist,
}

/// MPT start node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartNode {
    pub(crate) disable_preimage_check: bool,
    pub(crate) proof_type: MPTProofType,
}

/// MPT branch node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchNode {
    pub(crate) modified_index: usize,
    pub(crate) drifted_index: usize,
    pub(crate) list_rlp_bytes: [Vec<u8>; 2],
}

/// MPT extension node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionNode {
    pub(crate) list_rlp_bytes: Vec<u8>,
}

/// MPT extension branch node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionBranchNode {
    pub(crate) is_extension: bool,
    pub(crate) is_placeholder: [bool; 2],
    pub(crate) extension: ExtensionNode,
    pub(crate) branch: BranchNode,
}

/// MPT account node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountNode {
    pub(crate) address: Vec<u8>,
    pub(crate) key: Vec<u8>,
    pub(crate) list_rlp_bytes: [Vec<u8>; 2],
    pub(crate) value_rlp_bytes: [Vec<u8>; 2],
    pub(crate) value_list_rlp_bytes: [Vec<u8>; 2],
    pub(crate) drifted_rlp_bytes: Vec<u8>,
    pub(crate) wrong_rlp_bytes: Vec<u8>,
}

/// MPT storage node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageNode {
    pub(crate) address: Vec<u8>,
    pub(crate) key: Vec<u8>,
    pub(crate) list_rlp_bytes: [Vec<u8>; 2],
    pub(crate) value_rlp_bytes: [Vec<u8>; 2],
    pub(crate) drifted_rlp_bytes: Vec<u8>,
    pub(crate) wrong_rlp_bytes: Vec<u8>,
}

/// MPT node
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Node {
    pub(crate) start: Option<StartNode>,
    pub(crate) extension_branch: Option<ExtensionBranchNode>,
    pub(crate) account: Option<AccountNode>,
    pub(crate) storage: Option<StorageNode>,
    /// MPT node values
    pub values: Vec<Vec<u8>>,
    /// MPT keccak data
    pub keccak_data: Vec<Vec<u8>>,
}

/// Loads an MPT proof from disk
pub fn load_proof(path: &str) -> Vec<Node> {
    let file = std::fs::File::open(path);
    let reader = std::io::BufReader::new(file.unwrap());
    let mut nodes: Vec<Node> = serde_json::from_reader(reader).unwrap();

    // Add the address and the key to the list of values in the Account and Storage nodes
    for node in nodes.iter_mut() {
        if node.account.is_some() {
            let account = node.account.clone().unwrap();
            node.values.push([vec![148], account.address].concat());
            node.values.push([vec![160], account.key].concat());
        }
        if node.storage.is_some() {
            let storage: StorageNode = node.storage.clone().unwrap();
            node.values.push([vec![160], storage.address].concat());
            node.values.push([vec![160], storage.key].concat());
        }
    }
    nodes
}
