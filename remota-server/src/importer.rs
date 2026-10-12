//! mRemoteNG `confCons.xml` import (SidiOS research 015 R7, formats from 011 R16).
//!
//! The file is parsed with DTDs refused and bounded size, depth, and node count. Passwords are
//! decrypted in memory with the file's master password (or mRemoteNG's default key), placed in the
//! imported nodes as pending secrets, and sealed through webOS before anything is stored; Remota
//! never writes them. Supported: AES-256-GCM files (ConfVersion 2.6 and later, also full-file
//! encrypted) and legacy AES-128-CBC files. Other ciphers import the structure without passwords.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes_gcm::{
    aead::{consts::U16, Aead, KeyInit, Payload},
    AesGcm,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use md5::{Digest, Md5};
use roxmltree::{Document as Xml, ParsingOptions};
use serde::Serialize;
use sha1::Sha1;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{
    valid_host, Connection, Credentials, Node, Protocol, Secret, MAX_DEPTH, MAX_NAME, MAX_NODES,
};

/// Largest accepted file.
pub const MAX_FILE_BYTES: usize = 5 * 1024 * 1024;
/// Highest accepted `KdfIterations`, to bound the server's CPU time per password.
const MAX_ITERATIONS: u32 = 1_000_000;
/// Total PBKDF2 rounds one import may spend (about 100 passwords at the highest setting).
const ITERATION_BUDGET: u64 = 100_000_000;
const DEFAULT_PASSWORD: &str = "mR3m";

type Aes256Gcm16 = AesGcm<aes::Aes256, U16>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    InvalidFile,
    MasterPasswordRequired,
    WrongMasterPassword,
    TooManyIterations,
    UnsupportedCipher,
    TooDeep,
    TooManyNodes,
}

impl ImportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidFile => "invalid_file",
            Self::MasterPasswordRequired => "master_password_required",
            Self::WrongMasterPassword => "wrong_master_password",
            Self::TooManyIterations => "too_many_iterations",
            Self::UnsupportedCipher => "cipher_not_supported",
            Self::TooDeep => "too_deep",
            Self::TooManyNodes => "too_many_nodes",
        }
    }
}

/// Something the import left out, with a fixed reason code.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Skipped {
    pub name: String,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Default, PartialEq, Serialize)]
pub struct Report {
    pub folders: usize,
    pub connections: usize,
    pub passwords: usize,
    pub skipped: Vec<Skipped>,
}

/// The imported tree under one new folder; its passwords are still pending (unsealed) secrets.
pub struct Imported {
    pub root: Node,
    pub report: Report,
}

enum Cipher {
    Aead { iterations: u32 },
    Legacy,
    Unsupported,
}

struct Decryptor {
    cipher: Cipher,
    password: Zeroizing<String>,
    spent: std::cell::Cell<u64>,
}

impl Decryptor {
    fn new(cipher: Cipher, password: &str) -> Self {
        Self {
            cipher,
            password: Zeroizing::new(password.to_owned()),
            spent: std::cell::Cell::new(0),
        }
    }

    /// The plaintext, or `None` when the value does not decrypt with this key.
    fn decrypt(&self, encoded: &str) -> Result<Option<Zeroizing<String>>, ImportError> {
        let Ok(data) = STANDARD.decode(encoded.trim()) else {
            return Ok(None);
        };
        let plain = match self.cipher {
            Cipher::Aead { iterations } => {
                let spent = self.spent.get() + u64::from(iterations);
                if spent > ITERATION_BUDGET {
                    return Err(ImportError::TooManyIterations);
                }
                self.spent.set(spent);
                decrypt_gcm(&data, &self.password, iterations)
            }
            Cipher::Legacy => decrypt_cbc(&data, &self.password),
            Cipher::Unsupported => None,
        };
        Ok(plain.and_then(|mut bytes| {
            let text = String::from_utf8(std::mem::take(&mut bytes)).ok();
            bytes.zeroize();
            text.map(Zeroizing::new)
        }))
    }
}

/// AES-256-GCM: `salt[16] ‖ nonce[16] ‖ ciphertext ‖ tag[16]`, the salt as associated data, the key
/// from PBKDF2-HMAC-SHA1 over the low byte of each UTF-16 unit of the password.
fn decrypt_gcm(data: &[u8], password: &str, iterations: u32) -> Option<Vec<u8>> {
    if data.len() < 48 {
        return None;
    }
    let (salt, rest) = data.split_at(16);
    let (nonce, sealed) = rest.split_at(16);
    let mut secret: Vec<u8> = password.encode_utf16().map(|unit| unit as u8).collect();
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha1>(&secret, salt, iterations, key.as_mut());
    secret.zeroize();
    let cipher = Aes256Gcm16::new_from_slice(key.as_ref()).ok()?;
    cipher
        .decrypt(
            aes_gcm::Nonce::<U16>::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: salt,
            },
        )
        .ok()
}

/// Legacy AES-128-CBC: `iv[16] ‖ ciphertext`, the key the MD5 of the UTF-8 password.
fn decrypt_cbc(data: &[u8], password: &str) -> Option<Vec<u8>> {
    if data.len() < 32 || !data.len().is_multiple_of(16) {
        return None;
    }
    let (iv, sealed) = data.split_at(16);
    let key = Zeroizing::new(<[u8; 16]>::from(Md5::digest(password.as_bytes())));
    Aes128CbcDec::new_from_slices(key.as_ref(), iv)
        .ok()?
        .decrypt_padded_vec_mut::<Pkcs7>(sealed)
        .ok()
}

fn options() -> ParsingOptions {
    ParsingOptions {
        allow_dtd: false,
        nodes_limit: 200_000,
    }
}

fn is_true(element: roxmltree::Node, name: &str) -> bool {
    element
        .attribute(name)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn text(element: roxmltree::Node, name: &str) -> Option<String> {
    element
        .attribute(name)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(256).collect())
}

/// A display name the tree accepts: no control characters, at most 120 characters.
pub fn clean_name(raw: &str) -> String {
    let name: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect::<String>()
        .trim()
        .to_owned();
    if name.is_empty() {
        "(unnamed)".to_owned()
    } else {
        name
    }
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn conf_version(root: roxmltree::Node) -> f64 {
    root.attribute("ConfVersion")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0.0)
}

fn cipher_of(root: roxmltree::Node) -> Result<Cipher, ImportError> {
    if conf_version(root) < 2.6 {
        return Ok(Cipher::Legacy);
    }
    let engine = root.attribute("EncryptionEngine").unwrap_or("AES");
    let mode = root.attribute("BlockCipherMode").unwrap_or("GCM");
    if !engine.eq_ignore_ascii_case("AES") || !mode.eq_ignore_ascii_case("GCM") {
        return Ok(Cipher::Unsupported);
    }
    let iterations: u32 = match root.attribute("KdfIterations") {
        None => 1000,
        Some(value) => value.trim().parse().map_err(|_| ImportError::InvalidFile)?,
    };
    if iterations == 0 {
        return Err(ImportError::InvalidFile);
    }
    if iterations > MAX_ITERATIONS {
        return Err(ImportError::TooManyIterations);
    }
    Ok(Cipher::Aead { iterations })
}

/// Picks the key: mRemoteNG's default when `Protected` says the file has no master password,
/// otherwise the user's, which must decrypt `Protected` to `ThisIsProtected`.
fn decryptor(root: roxmltree::Node, master: Option<&str>) -> Result<Decryptor, ImportError> {
    let cipher = cipher_of(root)?;
    if matches!(cipher, Cipher::Unsupported) {
        return Ok(Decryptor::new(cipher, ""));
    }
    let Some(protected) = root.attribute("Protected") else {
        return Ok(Decryptor::new(cipher, DEFAULT_PASSWORD));
    };
    let default = Decryptor::new(cipher, DEFAULT_PASSWORD);
    if default.decrypt(protected)?.as_deref().map(String::as_str) == Some("ThisIsNotProtected") {
        return Ok(default);
    }
    let master = master
        .filter(|m| !m.is_empty())
        .ok_or(ImportError::MasterPasswordRequired)?;
    let custom = Decryptor::new(default.cipher, master);
    if custom.decrypt(protected)?.as_deref().map(String::as_str) == Some("ThisIsProtected") {
        Ok(custom)
    } else {
        Err(ImportError::WrongMasterPassword)
    }
}

struct Walk<'a> {
    decryptor: &'a Decryptor,
    report: Report,
    nodes: usize,
}

impl Walk<'_> {
    fn credentials(
        &mut self,
        element: roxmltree::Node,
        name: &str,
    ) -> Result<Credentials, ImportError> {
        let own = |flag: &str, attribute: &str| {
            if is_true(element, flag) {
                None
            } else {
                text(element, attribute)
            }
        };
        let mut secret = Secret::default();
        if !is_true(element, "InheritPassword") {
            if let Some(encrypted) = element.attribute("Password").filter(|p| !p.is_empty()) {
                match self.decryptor.decrypt(encrypted)? {
                    Some(plain) if !plain.is_empty() => {
                        secret.password = Some(plain.to_string());
                        self.report.passwords += 1;
                    }
                    Some(_) => {}
                    None => self.report.skipped.push(Skipped {
                        name: name.to_owned(),
                        reason: match self.decryptor.cipher {
                            Cipher::Unsupported => "cipher_not_supported",
                            _ => "password_unreadable",
                        },
                        detail: None,
                    }),
                }
            }
        }
        Ok(Credentials {
            username: own("InheritUsername", "Username"),
            domain: own("InheritDomain", "Domain"),
            secret,
        })
    }

    fn children(
        &mut self,
        parent: roxmltree::Node,
        level: usize,
    ) -> Result<Vec<Node>, ImportError> {
        let mut out = Vec::new();
        for element in parent
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "Node")
        {
            self.nodes += 1;
            if self.nodes >= MAX_NODES {
                return Err(ImportError::TooManyNodes);
            }
            let name = clean_name(element.attribute("Name").unwrap_or(""));
            let kind = element.attribute("Type").unwrap_or("Connection");
            if kind.eq_ignore_ascii_case("Container") {
                // `level` is this folder's depth in the tree, the import's own folder being 1.
                if level > MAX_DEPTH {
                    return Err(ImportError::TooDeep);
                }
                let defaults = self.credentials(element, &name)?;
                let children = self.children(element, level + 1)?;
                self.report.folders += 1;
                out.push(Node::Folder {
                    id: new_id(),
                    name,
                    defaults,
                    gateway: None,
                    icon: None,
                    children,
                });
            } else if let Some(node) = self.connection(element, name)? {
                out.push(node);
            }
        }
        Ok(out)
    }

    fn skip(&mut self, name: String, reason: &'static str, detail: Option<String>) {
        self.report.skipped.push(Skipped {
            name,
            reason,
            detail,
        });
    }

    fn connection(
        &mut self,
        element: roxmltree::Node,
        name: String,
    ) -> Result<Option<Node>, ImportError> {
        let raw_protocol = element.attribute("Protocol").unwrap_or("");
        let protocol = match raw_protocol.to_ascii_uppercase().as_str() {
            "RDP" => Protocol::Rdp,
            "SSH1" | "SSH2" | "SSH" => Protocol::Ssh,
            // Opened in the SidiOS Browser (US7); plain HTTP stays skipped.
            "HTTPS" => Protocol::Https,
            _ => {
                let detail = raw_protocol
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(20)
                    .collect();
                self.skip(name, "protocol_not_supported", Some(detail));
                return Ok(None);
            }
        };
        let host = element
            .attribute("Hostname")
            .unwrap_or("")
            .trim()
            .to_owned();
        if !valid_host(&host) {
            self.skip(name, "invalid_host", None);
            return Ok(None);
        }
        let port = element
            .attribute("Port")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .filter(|p| *p != 0 && *p != protocol.default_port());
        if protocol == Protocol::Rdp
            && text(element, "RDGatewayUsageMethod")
                .is_some_and(|m| !m.eq_ignore_ascii_case("Never"))
        {
            self.skip(name.clone(), "rdp_gateway_not_supported", None);
        }
        if text(element, "SSHTunnelConnectionName").is_some() {
            self.skip(name.clone(), "ssh_tunnel_not_supported", None);
        }
        let credentials = self.credentials(element, &name)?;
        self.report.connections += 1;
        Ok(Some(Node::Connection {
            id: new_id(),
            name,
            conn: Connection {
                protocol,
                host,
                port,
                credentials,
                gateway: None,
            },
        }))
    }
}

/// Parses an mRemoteNG file into one new folder named `folder_name`. Nothing is imported when
/// the master password is missing or wrong.
pub fn parse_mremoteng(
    xml: &str,
    folder_name: &str,
    master: Option<&str>,
) -> Result<Imported, ImportError> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let document = Xml::parse_with_options(xml, options()).map_err(|_| ImportError::InvalidFile)?;
    let root = document.root_element();
    if root.tag_name().name() != "Connections" {
        return Err(ImportError::InvalidFile);
    }
    let decryptor = decryptor(root, master)?;
    let mut walk = Walk {
        decryptor: &decryptor,
        report: Report::default(),
        nodes: 0,
    };
    let full_file = conf_version(root) >= 2.6 && is_true(root, "FullFileEncryption");
    let children = if full_file {
        if matches!(decryptor.cipher, Cipher::Unsupported) {
            return Err(ImportError::UnsupportedCipher);
        }
        let blob: String = root.children().filter_map(|n| n.text()).collect();
        let inner = decryptor.decrypt(&blob)?.ok_or(ImportError::InvalidFile)?;
        let wrapped = Zeroizing::new(format!("<Connections>{}</Connections>", inner.as_str()));
        let inner_document =
            Xml::parse_with_options(&wrapped, options()).map_err(|_| ImportError::InvalidFile)?;
        walk.children(inner_document.root_element(), 2)?
    } else {
        walk.children(root, 2)?
    };
    walk.report.folders += 1;
    Ok(Imported {
        root: Node::Folder {
            id: new_id(),
            name: clean_name(folder_name),
            defaults: Credentials::default(),
            gateway: None,
            icon: None,
            children,
        },
        report: walk.report,
    })
}

/// Removes every secret and credential reference: what an export contains and what a Remota JSON
/// import keeps. New IDs are given when `fresh_ids` is set.
pub fn strip_secrets(node: &mut Node, fresh_ids: bool) {
    match node {
        Node::Folder {
            id,
            defaults,
            gateway,
            children,
            ..
        } => {
            if fresh_ids {
                *id = new_id();
            }
            defaults.secret = Secret::default();
            if let Some(gateway) = gateway {
                gateway.secret = Secret::default();
            }
            for child in children {
                strip_secrets(child, fresh_ids);
            }
        }
        Node::Connection { id, conn, .. } => {
            if fresh_ids {
                *id = new_id();
            }
            conn.credentials.secret = Secret::default();
            if let Some(gateway) = &mut conn.gateway {
                gateway.secret = Secret::default();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/mremoteng/confCons.{name}.xml",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path).unwrap()
    }

    fn children(node: &Node) -> &[Node] {
        match node {
            Node::Folder { children, .. } => children,
            Node::Connection { .. } => &[],
        }
    }

    fn search<'a>(nodes: &'a [Node], name: &str) -> Option<&'a Node> {
        nodes.iter().find_map(|node| {
            if node.name() == name {
                Some(node)
            } else {
                search(children(node), name)
            }
        })
    }

    fn find<'a>(nodes: &'a [Node], name: &str) -> &'a Node {
        search(nodes, name).unwrap_or_else(|| panic!("{name} not imported"))
    }

    fn credentials(node: &Node) -> &Credentials {
        match node {
            Node::Folder { defaults, .. } => defaults,
            Node::Connection { conn, .. } => &conn.credentials,
        }
    }

    /// The shared expectations for every fixture whose passwords decrypt.
    fn assert_full_import(imported: &Imported) {
        let Node::Folder { name, children, .. } = &imported.root else {
            panic!("root is a folder");
        };
        assert_eq!(name, "confCons");
        let prod = find(children, "Prod");
        assert_eq!(credentials(prod).username.as_deref(), Some("ops"));
        assert_eq!(credentials(prod).domain.as_deref(), Some("CORP"));
        assert_eq!(
            credentials(prod).secret.password.as_deref(),
            Some("not-a-secret-folder")
        );

        let Node::Connection { conn: web, .. } = find(children, "web-1") else {
            panic!("web-1 is a connection");
        };
        assert_eq!(web.protocol, Protocol::Ssh);
        assert_eq!(web.host, "10.0.0.11");
        assert_eq!(web.port, Some(2222));
        // Inherited in mRemoteNG: left empty so Remota inherits from the folder.
        assert_eq!(web.credentials, Credentials::default());

        let Node::Connection { conn: win, .. } = find(children, "win-1") else {
            panic!("win-1 is a connection");
        };
        assert_eq!(win.protocol, Protocol::Rdp);
        assert_eq!(win.port, None, "the default port is not stored");
        assert_eq!(win.credentials.username.as_deref(), Some("administrator"));
        assert_eq!(
            win.credentials.secret.password.as_deref(),
            Some("not-a-secret-rdp")
        );

        let old = credentials(find(children, "old-ssh"));
        assert_eq!(old.username.as_deref(), Some("legacy"));
        assert_eq!(old.domain, None, "InheritDomain");
        assert_eq!(old.secret.password.as_deref(), Some("not-a-secret-ssh1"));

        let report = &imported.report;
        assert_eq!(
            (report.folders, report.connections, report.passwords),
            (3, 4, 4)
        );
        let skipped: Vec<(&str, &str)> = report
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.reason))
            .collect();
        assert_eq!(
            skipped,
            [
                ("vnc-1", "protocol_not_supported"),
                ("router", "protocol_not_supported")
            ]
        );
    }

    #[test]
    fn imports_https_connections_and_still_skips_plain_http() {
        let xml = r#"<Connections ConfVersion="2.5">
  <Node Name="router" Type="Connection" Protocol="HTTPS" Hostname="10.0.0.1" Port="8443" />
  <Node Name="old" Type="Connection" Protocol="HTTP" Hostname="10.0.0.2" Port="80" />
</Connections>"#;
        let imported = parse_mremoteng(xml, "f", None).unwrap();
        let Node::Folder { children, .. } = &imported.root else {
            panic!("root is a folder");
        };
        let Node::Connection { conn, .. } = &children[0] else {
            panic!("router is a connection");
        };
        assert_eq!((conn.protocol, conn.port), (Protocol::Https, Some(8443)));
        assert_eq!(children.len(), 1);
        assert_eq!(imported.report.skipped[0].name, "old");
        assert_eq!(imported.report.skipped[0].reason, "protocol_not_supported");
    }

    #[test]
    fn imports_a_gcm_file_saved_with_the_default_key_without_a_master_password() {
        assert_full_import(&parse_mremoteng(&fixture("gcm-default"), "confCons", None).unwrap());
    }

    #[test]
    fn imports_a_gcm_file_with_its_custom_master_password_only() {
        let xml = fixture("gcm-custom");
        assert_full_import(&parse_mremoteng(&xml, "confCons", Some("fixture-master-ü")).unwrap());
        assert_eq!(
            parse_mremoteng(&xml, "confCons", None).err(),
            Some(ImportError::MasterPasswordRequired)
        );
        assert_eq!(
            parse_mremoteng(&xml, "confCons", Some("wrong")).err(),
            Some(ImportError::WrongMasterPassword)
        );
    }

    #[test]
    fn imports_full_file_encryption_and_legacy_cbc() {
        assert_full_import(&parse_mremoteng(&fixture("gcm-fullfile"), "confCons", None).unwrap());
        assert_full_import(&parse_mremoteng(&fixture("cbc-legacy"), "confCons", None).unwrap());
    }

    #[test]
    fn imports_the_structure_of_an_unsupported_cipher_without_passwords() {
        let imported = parse_mremoteng(&fixture("twofish"), "confCons", None).unwrap();
        assert_eq!(imported.report.passwords, 0);
        assert_eq!(imported.report.connections, 4);
        assert_eq!(
            imported
                .report
                .skipped
                .iter()
                .filter(|s| s.reason == "cipher_not_supported")
                .count(),
            4
        );
        let full = fixture("twofish").replace(
            "FullFileEncryption=\"false\"",
            "FullFileEncryption=\"true\"",
        );
        assert_eq!(
            parse_mremoteng(&full, "confCons", None).err(),
            Some(ImportError::UnsupportedCipher)
        );
    }

    #[test]
    fn refuses_too_many_iterations_and_hostile_or_foreign_xml() {
        assert_eq!(
            parse_mremoteng(&fixture("iterations"), "confCons", None).err(),
            Some(ImportError::TooManyIterations)
        );
        let entity = r#"<?xml version="1.0"?>
<!DOCTYPE c [<!ENTITY x "xxxxxxxx"><!ENTITY y "&x;&x;&x;&x;&x;&x;">]>
<Connections ConfVersion="2.8"><Node Name="&y;" Type="Container"/></Connections>"#;
        assert_eq!(
            parse_mremoteng(entity, "f", None).err(),
            Some(ImportError::InvalidFile)
        );
        assert_eq!(
            parse_mremoteng("<html><body/></html>", "f", None).err(),
            Some(ImportError::InvalidFile)
        );
        assert_eq!(
            parse_mremoteng("not xml", "f", None).err(),
            Some(ImportError::InvalidFile)
        );
    }

    #[test]
    fn refuses_files_deeper_or_larger_than_the_tree_allows() {
        let open = "<Node Name=\"f\" Type=\"Container\">".repeat(MAX_DEPTH);
        let close = "</Node>".repeat(MAX_DEPTH);
        let deep = format!("<Connections ConfVersion=\"2.5\">{open}{close}</Connections>");
        assert_eq!(
            parse_mremoteng(&deep, "f", None).err(),
            Some(ImportError::TooDeep)
        );
        let many = format!(
            "<Connections ConfVersion=\"2.5\">{}</Connections>",
            "<Node Name=\"c\" Type=\"Connection\" Protocol=\"SSH2\" Hostname=\"h\"/>"
                .repeat(MAX_NODES)
        );
        assert_eq!(
            parse_mremoteng(&many, "f", None).err(),
            Some(ImportError::TooManyNodes)
        );
    }

    #[test]
    fn strips_every_secret_and_credential_reference() {
        let mut imported = parse_mremoteng(&fixture("gcm-default"), "confCons", None).unwrap();
        let before = serde_json::to_string(&imported.root).unwrap();
        strip_secrets(&mut imported.root, true);
        let after = serde_json::to_string(&imported.root).unwrap();
        assert!(!after.contains("not-a-secret"));
        assert!(!after.contains("credential_id"));
        assert_ne!(before, after, "IDs are fresh");
    }
}
