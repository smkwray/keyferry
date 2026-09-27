use keyferry_gateway::device_gateway_name;
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
};
use std::{io::Cursor, sync::Arc};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    Arc::new(provider)
}

fn certificate_pair(device_id: [u8; 16]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "Keyferry owner test root");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.distinguished_name = ca_name;
    ca_params.not_before = date_time_ymd(2020, 1, 1);
    ca_params.not_after = date_time_ymd(4096, 1, 1);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let name = device_gateway_name(&device_id).unwrap();
    let mut leaf_params = CertificateParams::new(vec![name]).unwrap();
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(4096, 1, 1);
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();
    (
        ca.der().to_vec(),
        leaf.der().to_vec(),
        leaf_key.serialize_der(),
    )
}

fn configs(
    ca_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_key_der: Vec<u8>,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der)).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();

    let server = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der)),
        )
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn handshake(
    name: String,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
) -> Result<ClientConnection, rustls::Error> {
    let mut client =
        ClientConnection::new(client_config, ServerName::try_from(name).unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    for _ in 0..32 {
        let mut to_server = Vec::new();
        client.write_tls(&mut to_server).unwrap();
        if !to_server.is_empty() {
            server.read_tls(&mut Cursor::new(to_server)).unwrap();
            server.process_new_packets()?;
        }

        let mut to_client = Vec::new();
        server.write_tls(&mut to_client).unwrap();
        if !to_client.is_empty() {
            client.read_tls(&mut Cursor::new(to_client)).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(client);
        }
    }
    Err(rustls::Error::General(
        "bounded in-memory handshake did not finish".to_owned(),
    ))
}

#[test]
fn device_scoped_owner_chain_uses_the_existing_tls_profile() {
    let device_id = [0x22; 16];
    let name = device_gateway_name(&device_id).unwrap();
    let (ca, leaf, key) = certificate_pair(device_id);
    let (client, server) = configs(ca, leaf, key);
    let connection = handshake(name, client, server).unwrap();
    assert_eq!(
        connection.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    assert_eq!(
        connection.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    );
    assert_eq!(connection.peer_certificates().unwrap().len(), 1);
}

#[test]
fn wrong_device_name_and_wrong_owner_fail_closed() {
    let device_id = [0x33; 16];
    let (ca, leaf, key) = certificate_pair(device_id);
    let (client, server) = configs(ca, leaf, key);
    let wrong_name = device_gateway_name(&[0x34; 16]).unwrap();
    assert!(handshake(wrong_name, client, server).is_err());

    let (_, leaf, key) = certificate_pair(device_id);
    let (other_ca, _, _) = certificate_pair([0x55; 16]);
    let (client, server) = configs(other_ca, leaf, key);
    assert!(handshake(device_gateway_name(&device_id).unwrap(), client, server).is_err());
}
