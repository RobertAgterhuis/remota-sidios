//! The connection tree, in upstream Remota's shape (`src-tauri/src/model`), adapted for SidiOS:
//! secrets are write-only. A client may send a password or private key with a node; the server
//! seals it in the SidiOS vault, keeps only the returned `credential_id`, and never serializes a
//! secret back. Folders pass username, domain, credential, and jump host down to their contents.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const MAX_DEPTH: usize = 10;
pub const MAX_NODES: usize = 5_000;
pub const MAX_NAME: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Rdp,
    /// A web console, opened in the SidiOS Browser; Remota starts no session for it (US7).
    Https,
    /// Plain FTP: the server signs in with the stored password, sent unencrypted to the target (US8).
    Ftp,
    /// FTP over TLS: explicit (AUTH TLS) on any port, implicit on 990 (US8).
    Ftps,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Https => "https",
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Rdp => 3389,
            Self::Https => 443,
            Self::Ftp | Self::Ftps => 21,
        }
    }

    pub fn is_file_transfer(self) -> bool {
        matches!(self, Self::Ftp | Self::Ftps)
    }
}

/// A reference to a sealed credential plus, on the way in only, a new secret to seal.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    #[serde(default, skip_serializing)]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing)]
    pub passphrase: Option<String>,
}

impl Secret {
    /// The new secret to seal, if the client sent one: (kind, secret, passphrase).
    pub fn pending(&self) -> Option<(&'static str, &str, Option<&str>)> {
        if let Some(key) = self.private_key.as_deref().filter(|k| !k.is_empty()) {
            return Some(("private_key", key, self.passphrase.as_deref()));
        }
        self.password
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|password| ("password", password, None))
    }

    pub fn clear_pending(&mut self) {
        self.password = None;
        self.private_key = None;
        self.passphrase = None;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(flatten)]
    pub secret: Secret,
}

/// Jump host (SSH ProxyJump): the target is reached through it, with its own credential.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Gateway {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(flatten)]
    pub secret: Secret,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: Protocol,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub credentials: Credentials,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Gateway>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Node {
    Folder {
        id: String,
        name: String,
        #[serde(default)]
        defaults: Credentials,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<Gateway>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        icon: Option<String>,
        #[serde(default)]
        children: Vec<Node>,
    },
    Connection {
        id: String,
        name: String,
        conn: Connection,
    },
}

impl Node {
    pub fn id(&self) -> &str {
        match self {
            Node::Folder { id, .. } | Node::Connection { id, .. } => id,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Node::Folder { name, .. } | Node::Connection { name, .. } => name,
        }
    }

    /// Every credential slot of this node (not its children), with a label for the vault.
    pub fn secrets_mut(&mut self) -> Vec<(String, Option<String>, &mut Secret)> {
        let label = self.name().to_owned();
        let (credentials, gateway) = match self {
            Node::Folder {
                defaults, gateway, ..
            } => (defaults, gateway.as_mut()),
            Node::Connection { conn, .. } => (&mut conn.credentials, conn.gateway.as_mut()),
        };
        let mut slots = vec![(
            label.clone(),
            credentials.username.clone(),
            &mut credentials.secret,
        )];
        if let Some(gateway) = gateway {
            slots.push((
                format!("{label} (jump host)"),
                gateway.username.clone(),
                &mut gateway.secret,
            ));
        }
        slots
    }

    fn children(&self) -> &[Node] {
        match self {
            Node::Folder { children, .. } => children,
            Node::Connection { .. } => &[],
        }
    }
}

/// Trash entry: the removed node and the folder it came from (to restore it in place).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrashEntry {
    pub node: Node,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Document {
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub trash: Vec<TrashEntry>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TreeError {
    Invalid(&'static str),
    NotFound,
}

pub type TreeResult<T> = Result<T, TreeError>;

impl Document {
    pub fn find(&self, id: &str) -> Option<&Node> {
        find_in(&self.nodes, id)
    }

    /// Creates `node` under `parent_id`, or updates and moves the existing node with its ID. An
    /// existing folder keeps its own children; a new folder starts empty.
    pub fn upsert(&mut self, parent_id: Option<&str>, node: Node) -> TreeResult<()> {
        let before = self.clone();
        let result = self.place(parent_id, node);
        if result.is_err() {
            *self = before;
        }
        result
    }

    fn place(&mut self, parent_id: Option<&str>, mut node: Node) -> TreeResult<()> {
        validate_node(&node)?;
        if self
            .trash
            .iter()
            .any(|entry| contains(&entry.node, node.id()))
        {
            return Err(TreeError::Invalid("node_in_trash"));
        }
        let existing = self.remove_returning(node.id());
        if let Node::Folder { children, .. } = &mut node {
            *children = match existing {
                Some((Node::Folder { children: old, .. }, _)) => old,
                _ => Vec::new(),
            };
        }
        self.insert(parent_id, node)?;
        self.check_limits()
    }

    /// Soft delete: moves the node (and everything inside) to the trash.
    pub fn delete(&mut self, id: &str) -> TreeResult<()> {
        let (node, parent_id) = self.remove_returning(id).ok_or(TreeError::NotFound)?;
        self.trash.push(TrashEntry { node, parent_id });
        Ok(())
    }

    /// Restores a trashed node to its old folder, or to the top level if that folder is gone.
    pub fn restore(&mut self, id: &str) -> TreeResult<()> {
        let position = self.trash_position(id)?;
        let entry = self.trash.remove(position);
        let parent = entry
            .parent_id
            .as_deref()
            .filter(|parent| matches!(self.find(parent), Some(Node::Folder { .. })));
        self.insert(parent.map(str::to_owned).as_deref(), entry.node)
    }

    pub fn delete_forever(&mut self, id: &str) -> TreeResult<()> {
        let position = self.trash_position(id)?;
        self.trash.remove(position);
        Ok(())
    }

    pub fn empty_trash(&mut self) {
        self.trash.clear();
    }

    /// Adds imported nodes at the top level; answers how many connections arrived.
    pub fn import(&mut self, nodes: Vec<Node>) -> TreeResult<usize> {
        for node in &nodes {
            validate_tree(node, 1)?;
        }
        let count = count_connections(&nodes);
        self.nodes.extend(nodes);
        self.check_limits()?;
        Ok(count)
    }

    /// Every credential ID the tree or the trash still uses.
    pub fn credential_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        let trashed = self.trash.iter().map(|entry| &entry.node);
        for node in self.nodes.iter().chain(trashed) {
            collect_credential_ids(node, &mut ids);
        }
        ids
    }

    /// The folders from the top level down to the connection's parent, and the connection.
    pub fn connection_with_chain(&self, id: &str) -> Option<(Vec<&Node>, &Node)> {
        chain_to(&self.nodes, id, Vec::new())
    }

    fn trash_position(&self, id: &str) -> TreeResult<usize> {
        self.trash
            .iter()
            .position(|entry| entry.node.id() == id)
            .ok_or(TreeError::NotFound)
    }

    fn insert(&mut self, parent_id: Option<&str>, node: Node) -> TreeResult<()> {
        let Some(parent_id) = parent_id else {
            self.nodes.push(node);
            return Ok(());
        };
        match find_folder_children(&mut self.nodes, parent_id) {
            Some(children) => {
                children.push(node);
                Ok(())
            }
            None => Err(TreeError::Invalid("parent_not_found")),
        }
    }

    fn remove_returning(&mut self, id: &str) -> Option<(Node, Option<String>)> {
        remove_in(&mut self.nodes, id, None)
    }

    fn check_limits(&self) -> TreeResult<()> {
        let total: usize = self.nodes.iter().map(count_nodes).sum();
        if total > MAX_NODES {
            return Err(TreeError::Invalid("too_many_nodes"));
        }
        if self.nodes.iter().any(|node| depth(node) > MAX_DEPTH) {
            return Err(TreeError::Invalid("too_deep"));
        }
        Ok(())
    }
}

/// What a connection uses after inheritance: its own value, else the nearest folder's.
#[derive(Clone, Debug, PartialEq)]
pub struct Effective {
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub credential_id: Option<String>,
    pub jump: Option<EffectiveJump>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EffectiveJump {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub credential_id: Option<String>,
}

impl Document {
    /// Resolves a connection's effective settings, or `None` if `id` is not an active connection.
    pub fn effective(&self, id: &str) -> Option<Effective> {
        let (chain, node) = self.connection_with_chain(id)?;
        let Node::Connection { name, conn, .. } = node else {
            return None;
        };
        let folders: Vec<(&Credentials, Option<&Gateway>)> = chain
            .iter()
            .rev()
            .filter_map(|folder| match folder {
                Node::Folder {
                    defaults, gateway, ..
                } => Some((defaults, gateway.as_ref())),
                Node::Connection { .. } => None,
            })
            .collect();
        let own = &conn.credentials;
        let inherit = |pick: &dyn Fn(&Credentials) -> Option<String>| {
            pick(own).or_else(|| folders.iter().find_map(|(defaults, _)| pick(defaults)))
        };
        let username = inherit(&|c| c.username.clone());
        let credential_id = inherit(&|c| c.secret.credential_id.clone());
        let gateway = conn
            .gateway
            .as_ref()
            .or_else(|| folders.iter().find_map(|(_, gateway)| *gateway));
        Some(Effective {
            name: name.clone(),
            protocol: conn.protocol,
            host: conn.host.clone(),
            port: conn.port.unwrap_or(conn.protocol.default_port()),
            domain: inherit(&|c| c.domain.clone()),
            jump: gateway.map(|g| EffectiveJump {
                host: g.host.clone(),
                port: g.port.unwrap_or(22),
                // A jump host without its own login uses the connection's.
                username: g.username.clone().or_else(|| username.clone()),
                credential_id: g
                    .secret
                    .credential_id
                    .clone()
                    .or_else(|| credential_id.clone()),
            }),
            username,
            credential_id,
        })
    }

    /// Points the connection's own credential at `credential_id` (a secret saved at connect time).
    pub fn set_connection_credential(&mut self, id: &str, credential_id: String) -> TreeResult<()> {
        match find_in_mut(&mut self.nodes, id) {
            Some(Node::Connection { conn, .. }) => {
                conn.credentials.secret.credential_id = Some(credential_id);
                Ok(())
            }
            _ => Err(TreeError::NotFound),
        }
    }
}

fn find_in_mut<'a>(nodes: &'a mut [Node], id: &str) -> Option<&'a mut Node> {
    for node in nodes.iter_mut() {
        if node.id() == id {
            return Some(node);
        }
        if let Node::Folder { children, .. } = node {
            if let Some(found) = find_in_mut(children, id) {
                return Some(found);
            }
        }
    }
    None
}

fn find_in<'a>(nodes: &'a [Node], id: &str) -> Option<&'a Node> {
    nodes.iter().find_map(|node| {
        if node.id() == id {
            Some(node)
        } else {
            find_in(node.children(), id)
        }
    })
}

fn contains(node: &Node, id: &str) -> bool {
    node.id() == id || node.children().iter().any(|child| contains(child, id))
}

fn find_folder_children<'a>(nodes: &'a mut [Node], id: &str) -> Option<&'a mut Vec<Node>> {
    for node in nodes.iter_mut() {
        if let Node::Folder {
            id: folder_id,
            children,
            ..
        } = node
        {
            if folder_id == id {
                return Some(children);
            }
            if let Some(found) = find_folder_children(children, id) {
                return Some(found);
            }
        }
    }
    None
}

fn remove_in(
    nodes: &mut Vec<Node>,
    id: &str,
    parent: Option<&str>,
) -> Option<(Node, Option<String>)> {
    if let Some(position) = nodes.iter().position(|node| node.id() == id) {
        return Some((nodes.remove(position), parent.map(str::to_owned)));
    }
    nodes.iter_mut().find_map(|node| match node {
        Node::Folder {
            id: folder_id,
            children,
            ..
        } => {
            let folder_id = folder_id.clone();
            remove_in(children, id, Some(&folder_id))
        }
        Node::Connection { .. } => None,
    })
}

fn chain_to<'a>(
    nodes: &'a [Node],
    id: &str,
    chain: Vec<&'a Node>,
) -> Option<(Vec<&'a Node>, &'a Node)> {
    for node in nodes {
        match node {
            Node::Connection { id: own, .. } if own == id => return Some((chain, node)),
            Node::Folder { children, .. } => {
                let mut deeper = chain.clone();
                deeper.push(node);
                if let Some(found) = chain_to(children, id, deeper) {
                    return Some(found);
                }
            }
            Node::Connection { .. } => {}
        }
    }
    None
}

fn collect_credential_ids(node: &Node, ids: &mut BTreeSet<String>) {
    let (credentials, gateway) = match node {
        Node::Folder {
            defaults, gateway, ..
        } => (defaults, gateway.as_ref()),
        Node::Connection { conn, .. } => (&conn.credentials, conn.gateway.as_ref()),
    };
    let secrets = std::iter::once(&credentials.secret).chain(gateway.map(|g| &g.secret));
    ids.extend(secrets.filter_map(|secret| secret.credential_id.clone()));
    for child in node.children() {
        collect_credential_ids(child, ids);
    }
}

pub fn count_connections(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|node| match node {
            Node::Connection { .. } => 1,
            Node::Folder { children, .. } => count_connections(children),
        })
        .sum()
}

fn count_nodes(node: &Node) -> usize {
    1 + node.children().iter().map(count_nodes).sum::<usize>()
}

fn depth(node: &Node) -> usize {
    match node {
        Node::Folder { children, .. } => 1 + children.iter().map(depth).max().unwrap_or(0),
        Node::Connection { .. } => 0,
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && name.chars().count() <= MAX_NAME && !name.chars().any(char::is_control)
}

/// A host name or address: no spaces, no scheme, no path; at most 253 characters.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
}

fn validate_node(node: &Node) -> TreeResult<()> {
    if !valid_id(node.id()) {
        return Err(TreeError::Invalid("invalid_id"));
    }
    if !valid_name(node.name()) {
        return Err(TreeError::Invalid("invalid_name"));
    }
    let gateway = match node {
        Node::Folder { gateway, .. } => gateway.as_ref(),
        Node::Connection { conn, .. } => {
            if !valid_host(&conn.host) || conn.port == Some(0) {
                return Err(TreeError::Invalid("invalid_host"));
            }
            conn.gateway.as_ref()
        }
    };
    match gateway {
        Some(gateway) if !valid_host(&gateway.host) || gateway.port == Some(0) => {
            Err(TreeError::Invalid("invalid_jump_host"))
        }
        _ => Ok(()),
    }
}

fn validate_tree(node: &Node, level: usize) -> TreeResult<()> {
    validate_node(node)?;
    if level > MAX_DEPTH + 1 {
        return Err(TreeError::Invalid("too_deep"));
    }
    node.children()
        .iter()
        .try_for_each(|child| validate_tree(child, level + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: &str) -> Node {
        Node::Connection {
            id: id.into(),
            name: id.into(),
            conn: Connection {
                protocol: Protocol::Ssh,
                host: "10.0.0.1".into(),
                port: None,
                credentials: Credentials::default(),
                gateway: None,
            },
        }
    }

    fn folder(id: &str, children: Vec<Node>) -> Node {
        Node::Folder {
            id: id.into(),
            name: id.into(),
            defaults: Credentials::default(),
            gateway: None,
            icon: None,
            children,
        }
    }

    fn with_secret(id: &str, credential_id: &str) -> Node {
        let mut node = conn(id);
        if let Node::Connection { conn, .. } = &mut node {
            conn.credentials.secret.credential_id = Some(credential_id.into());
        }
        node
    }

    #[test]
    fn never_serializes_a_secret() {
        let mut node = conn("c1");
        if let Node::Connection { conn, .. } = &mut node {
            conn.credentials.secret = Secret {
                credential_id: Some("cred".into()),
                password: Some("hunter2".into()),
                private_key: Some("-----BEGIN KEY".into()),
                passphrase: Some("pp".into()),
            };
        }
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("\"credential_id\":\"cred\""));
        for secret in [
            "hunter2",
            "BEGIN KEY",
            "\"pp\"",
            "password",
            "private_key",
            "passphrase",
        ] {
            assert!(!json.contains(secret), "{secret} leaked: {json}");
        }
    }

    #[test]
    fn accepts_write_only_secrets_from_clients() {
        let node: Node = serde_json::from_str(
            r#"{"type":"connection","id":"c1","name":"web",
                "conn":{"protocol":"ssh","host":"h","credentials":{"username":"root","password":"pw"}}}"#,
        )
        .unwrap();
        let Node::Connection { conn, .. } = node else {
            panic!()
        };
        assert_eq!(
            conn.credentials.secret.pending(),
            Some(("password", "pw", None))
        );
    }

    #[test]
    fn prefers_a_private_key_over_a_password() {
        let secret = Secret {
            password: Some("pw".into()),
            private_key: Some("key".into()),
            passphrase: Some("pp".into()),
            ..Secret::default()
        };
        assert_eq!(secret.pending(), Some(("private_key", "key", Some("pp"))));
        assert_eq!(Secret::default().pending(), None);
    }

    #[test]
    fn upsert_creates_and_moves_while_folders_keep_their_children() {
        let mut doc = Document::default();
        doc.upsert(None, folder("a", vec![])).unwrap();
        doc.upsert(None, folder("b", vec![])).unwrap();
        doc.upsert(Some("a"), conn("c1")).unwrap();

        // The client sends the folder without children; the server keeps them.
        doc.upsert(Some("b"), folder("a", vec![])).unwrap();
        let (chain, _) = doc.connection_with_chain("c1").unwrap();
        assert_eq!(chain.iter().map(|n| n.id()).collect::<Vec<_>>(), ["b", "a"]);
    }

    #[test]
    fn a_new_folder_cannot_smuggle_children_in() {
        let mut doc = Document::default();
        doc.upsert(None, folder("a", vec![conn("c1")])).unwrap();
        assert!(doc.find("c1").is_none());
    }

    #[test]
    fn refuses_moving_a_folder_into_itself_and_keeps_the_tree() {
        let mut doc = Document::default();
        doc.upsert(None, folder("a", vec![])).unwrap();
        doc.upsert(Some("a"), folder("b", vec![])).unwrap();
        assert_eq!(
            doc.upsert(Some("b"), folder("a", vec![])),
            Err(TreeError::Invalid("parent_not_found"))
        );
        assert!(doc.find("a").is_some());
        assert!(doc.find("b").is_some());
    }

    #[test]
    fn refuses_unknown_parents_and_invalid_input() {
        let mut doc = Document::default();
        assert!(doc.upsert(Some("missing"), conn("c1")).is_err());
        assert!(doc.find("c1").is_none());
        assert!(doc.upsert(None, conn("bad id")).is_err());
        let mut bad_host = conn("c2");
        if let Node::Connection { conn, .. } = &mut bad_host {
            conn.host = "evil host/path".into();
        }
        assert_eq!(
            doc.upsert(None, bad_host),
            Err(TreeError::Invalid("invalid_host"))
        );
    }

    #[test]
    fn limits_depth_to_ten_folder_levels() {
        let mut doc = Document::default();
        let mut parent: Option<String> = None;
        for level in 0..MAX_DEPTH {
            let id = format!("f{level}");
            doc.upsert(parent.as_deref(), folder(&id, vec![])).unwrap();
            parent = Some(id);
        }
        assert_eq!(
            doc.upsert(parent.as_deref(), folder("too-deep", vec![])),
            Err(TreeError::Invalid("too_deep"))
        );
        assert!(doc.find("too-deep").is_none());
    }

    #[test]
    fn trash_keeps_contents_and_restores_in_place_or_at_the_top() {
        let mut doc = Document::default();
        doc.upsert(None, folder("a", vec![])).unwrap();
        doc.upsert(Some("a"), folder("b", vec![])).unwrap();
        doc.upsert(Some("b"), conn("c1")).unwrap();

        doc.delete("b").unwrap();
        assert!(doc.find("c1").is_none());
        doc.restore("b").unwrap();
        assert_eq!(doc.connection_with_chain("c1").unwrap().0.len(), 2);

        doc.delete("c1").unwrap();
        doc.delete("a").unwrap();
        doc.restore("c1").unwrap();
        assert!(
            doc.nodes.iter().any(|n| n.id() == "c1"),
            "restored at top level"
        );
    }

    #[test]
    fn deleting_forever_and_emptying_the_trash() {
        let mut doc = Document::default();
        doc.upsert(None, conn("c1")).unwrap();
        doc.upsert(None, conn("c2")).unwrap();
        doc.delete("c1").unwrap();
        doc.delete("c2").unwrap();
        doc.delete_forever("c1").unwrap();
        assert_eq!(doc.trash.len(), 1);
        assert_eq!(doc.delete_forever("c1"), Err(TreeError::NotFound));
        doc.empty_trash();
        assert!(doc.trash.is_empty());
    }

    #[test]
    fn a_trashed_node_cannot_be_recreated_under_its_id() {
        let mut doc = Document::default();
        doc.upsert(None, conn("c1")).unwrap();
        doc.delete("c1").unwrap();
        assert_eq!(
            doc.upsert(None, conn("c1")),
            Err(TreeError::Invalid("node_in_trash"))
        );
    }

    #[test]
    fn resolves_the_nearest_folder_for_each_missing_value() {
        let mut doc = Document::default();
        let mut outer = folder("outer", vec![]);
        if let Node::Folder {
            defaults, gateway, ..
        } = &mut outer
        {
            defaults.username = Some("root".into());
            defaults.domain = Some("CORP".into());
            defaults.secret.credential_id = Some("outer-key".into());
            *gateway = Some(Gateway {
                host: "bastion".into(),
                ..Gateway::default()
            });
        }
        let mut inner = folder("inner", vec![]);
        if let Node::Folder { defaults, .. } = &mut inner {
            defaults.username = Some("deploy".into());
        }
        doc.upsert(None, outer).unwrap();
        doc.upsert(Some("outer"), inner).unwrap();
        doc.upsert(Some("inner"), conn("web")).unwrap();

        let effective = doc.effective("web").unwrap();
        assert_eq!(effective.username.as_deref(), Some("deploy"));
        assert_eq!(effective.domain.as_deref(), Some("CORP"));
        assert_eq!(effective.credential_id.as_deref(), Some("outer-key"));
        assert_eq!(effective.port, 22);
        let jump = effective.jump.unwrap();
        assert_eq!((jump.host.as_str(), jump.port), ("bastion", 22));
        assert_eq!(
            jump.username.as_deref(),
            Some("deploy"),
            "falls back to the connection's"
        );
        assert_eq!(jump.credential_id.as_deref(), Some("outer-key"));
        assert!(
            doc.effective("inner").is_none(),
            "folders are not connections"
        );
        assert!(doc.effective("missing").is_none());
    }

    #[test]
    fn a_connections_own_values_win() {
        let mut doc = Document::default();
        let mut outer = folder("outer", vec![]);
        if let Node::Folder { defaults, .. } = &mut outer {
            defaults.username = Some("root".into());
        }
        doc.upsert(None, outer).unwrap();
        doc.upsert(Some("outer"), with_secret("web", "own-key"))
            .unwrap();
        doc.set_connection_credential("web", "newer".into())
            .unwrap();
        let effective = doc.effective("web").unwrap();
        assert_eq!(effective.username.as_deref(), Some("root"));
        assert_eq!(effective.credential_id.as_deref(), Some("newer"));
        assert!(effective.jump.is_none());
    }

    #[test]
    fn lists_credential_ids_in_the_tree_and_the_trash() {
        let mut doc = Document::default();
        doc.upsert(None, with_secret("c1", "k1")).unwrap();
        doc.upsert(None, with_secret("c2", "k2")).unwrap();
        doc.delete("c2").unwrap();
        assert_eq!(
            doc.credential_ids().into_iter().collect::<Vec<_>>(),
            ["k1", "k2"]
        );
    }
}
