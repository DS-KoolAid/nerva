# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Troubleshooting section in README
- CONTRIBUTING.md with plugin development guide
- SECURITY.md with vulnerability reporting policy
- Dynamic badges for release version, build status, and Go report card

### Changed
- Improved README with keyword-rich descriptions for SEO
- Updated repository topics for better discoverability

## [1.0.0] - 2024-01-XX

### Added
- Initial release as Nerva (fork of fingerprintx)
- 51 service detection plugins supporting TCP and UDP protocols
- Vector database support: ChromaDB, Milvus, Pinecone
- Industrial protocol support: Modbus, IPMI
- Telecom protocol support: Diameter (3GPP/LTE/5G), SMPP
- JSON and CSV output formats
- Fast mode for default-port-only scanning
- Docker support
- Library usage with examples

### Supported Protocols
- **Databases**: PostgreSQL, MySQL, MSSQL, OracleDB, MongoDB, Redis, Cassandra, CouchDB, Elasticsearch, InfluxDB, Neo4j, DB2, Sybase, Firebird, Memcached
- **Vector Databases**: ChromaDB, Milvus, Pinecone
- **Remote Access**: SSH, RDP, Telnet, VNC
- **Web**: HTTP/HTTPS
- **File Transfer**: FTP, SMB, Rsync
- **Messaging**: Kafka, MQTT, SMTP, POP3, IMAP
- **Directory**: LDAP
- **Network Services**: DNS, DHCP, NTP, SNMP, NetBIOS-NS
- **VPN**: OpenVPN, IPsec
- **Industrial**: Modbus, IPMI
- **Telecom**: Diameter, SMPP
- **Developer Tools**: JDWP, Java RMI
- **Other**: RTSP, Echo, SNPP, STUN, Linux RPC

## Attribution

Nerva is a maintained fork of [fingerprintx](https://github.com/praetorian-inc/fingerprintx), originally developed by Praetorian's intern class of 2022.
