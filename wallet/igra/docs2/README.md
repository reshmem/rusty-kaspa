# Igra Documentation

**Last Updated:** 2026-02-05

Welcome to the Igra documentation. This guide is organized by audience to help you find exactly what you need.

---

## What is Igra?

Igra is a **leaderless threshold signature coordination system** for UTXO-based blockchains. It enables multiple independent signers to safely coordinate threshold-signed transactions without requiring leader election or trusted coordinators.

**Key Features:**
- ✅ **Leaderless coordination** - No single point of failure
- ✅ **Safety-first design** - Prevents double-spending under UTXO divergence
- ✅ **CRDT-based signature collection** - Efficient, fault-tolerant gathering of partial signatures
- ✅ **Cross-chain bridge support** - Hyperlane, LayerZero, and custom validators
- ✅ **Production-ready** - Deployed on Kaspa blockchain

---

## Choose Your Path

### 👤 I want to understand what Igra does
**Audience:** Product managers, stakeholders, general users

**Start here:**
1. [What is Igra?](overview/01-what-is-igra.md) - High-level overview
2. [Use Cases](overview/02-use-cases.md) - Real-world applications
3. [How It Works](overview/03-how-it-works.md) - Non-technical explanation
4. [FAQ](overview/04-faq.md) - Common questions

**Time:** 20-30 minutes

---

### 🎛️ I need to deploy and operate Igra
**Audience:** DevOps engineers, system administrators, operators

**Start here:**
1. [Quick Start - Devnet](operators/deployment/01-quickstart-devnet.md) - Get running in 15 minutes
2. [Configuration Guide](operators/configuration/01-configuration-overview.md) - Complete config reference
3. [Deployment - Testnet](operators/deployment/02-deployment-testnet.md) - Production-like setup
4. [Deployment - Mainnet](operators/deployment/03-deployment-mainnet.md) - Production deployment
5. [Monitoring](operators/monitoring/01-monitoring-overview.md) - Observability and alerts

**Time:** 2-4 hours (quickstart) | 1-2 days (production deployment)

---

### 👨‍💻 I want to develop or contribute code
**Audience:** Software engineers, contributors, auditors

**Start here:**
1. [Architecture Overview](developers/architecture/01-architecture-overview.md) - System design
2. [Protocol Specification](developers/architecture/02-protocol-specification.md) - Formal protocol description
3. [Code Guidelines](developers/contributing/01-code-guidelines.md) - Coding standards
4. [API Reference](developers/api/01-api-overview.md) - REST API documentation
5. [Development Setup](developers/contributing/02-development-setup.md) - Local dev environment

**Time:** 4-6 hours (architecture understanding) | 1-2 weeks (contribution ready)

---

### 🔧 I manage infrastructure and security
**Audience:** Infrastructure engineers, security engineers, IT managers

**Start here:**
1. [Infrastructure Requirements](devops/infrastructure/01-requirements.md) - Hardware, network, storage
2. [Networking Guide](devops/networking/01-networking-overview.md) - P2P gossip, firewalls, discovery
3. [Security Best Practices](devops/security/01-security-overview.md) - Key management, access control
4. [Operations Runbook](devops/operations/01-operations-runbook.md) - Day-to-day operations
5. [Disaster Recovery](devops/operations/02-disaster-recovery.md) - Backup and recovery procedures

**Time:** 3-5 hours (initial setup) | Ongoing maintenance

---

## Documentation Structure

```
docs2/
├── README.md (this file)
│
├── overview/                    # For everyone
│   ├── 01-what-is-igra.md
│   ├── 02-use-cases.md
│   ├── 03-how-it-works.md
│   └── 04-faq.md
│
├── operators/                   # For operators & sysadmins
│   ├── deployment/
│   │   ├── 01-quickstart-devnet.md
│   │   ├── 02-deployment-testnet.md
│   │   └── 03-deployment-mainnet.md
│   ├── configuration/
│   │   ├── 01-configuration-overview.md
│   │   ├── 02-network-modes.md
│   │   ├── 03-secrets-and-keys.md
│   │   ├── 04-hyperlane-config.md
│   │   └── 05-advanced-configuration.md
│   ├── monitoring/
│   │   ├── 01-monitoring-overview.md
│   │   ├── 02-metrics-reference.md
│   │   └── 03-alerting.md
│   └── troubleshooting/
│       ├── 01-common-issues.md
│       ├── 02-debugging-guide.md
│       └── 03-failure-scenarios.md
│
├── developers/                  # For software engineers
│   ├── architecture/
│   │   ├── 01-architecture-overview.md
│   │   ├── 02-protocol-specification.md
│   │   ├── 03-two-phase-coordination.md
│   │   ├── 04-crdt-signing.md
│   │   ├── 05-utxo-coordination-problem.md
│   │   └── 06-codebase-structure.md
│   ├── api/
│   │   ├── 01-api-overview.md
│   │   ├── 02-rest-api.md
│   │   ├── 03-websocket-api.md
│   │   └── 04-client-libraries.md
│   ├── contributing/
│   │   ├── 01-code-guidelines.md
│   │   ├── 02-development-setup.md
│   │   ├── 03-testing-guide.md
│   │   ├── 04-pull-request-process.md
│   │   └── 05-release-process.md
│   └── design/
│       ├── 01-design-decisions.md
│       ├── 02-utxo-consolidation.md
│       └── 03-future-enhancements.md
│
└── devops/                      # For infrastructure & security
    ├── infrastructure/
    │   ├── 01-requirements.md
    │   ├── 02-sizing-guide.md
    │   └── 03-cloud-deployment.md
    ├── networking/
    │   ├── 01-networking-overview.md
    │   ├── 02-iroh-p2p.md
    │   ├── 03-firewall-rules.md
    │   └── 04-discovery-bootstrap.md
    ├── security/
    │   ├── 01-security-overview.md
    │   ├── 02-key-management.md
    │   ├── 03-passphrase-rotation.md
    │   ├── 04-timing-attacks.md
    │   └── 05-audit-compliance.md
    └── operations/
        ├── 01-operations-runbook.md
        ├── 02-disaster-recovery.md
        ├── 03-backup-procedures.md
        └── 04-upgrade-procedures.md
```

---

## Quick Reference

### Essential Reading (Everyone)
1. [What is Igra?](overview/01-what-is-igra.md) - 5 minutes
2. [Protocol Specification](developers/architecture/02-protocol-specification.md) - 30 minutes
3. [Security Overview](devops/security/01-security-overview.md) - 15 minutes

### Deployment Paths
- **Testing/Development**: [Devnet Quickstart](operators/deployment/01-quickstart-devnet.md) → 15 minutes
- **Staging/Integration**: [Testnet Deployment](operators/deployment/02-deployment-testnet.md) → 2-4 hours
- **Production**: [Mainnet Deployment](operators/deployment/03-deployment-mainnet.md) → 1-2 days

### Common Tasks
- Configure network → [Configuration Overview](operators/configuration/01-configuration-overview.md)
- Add validator keys → [Hyperlane Config](operators/configuration/04-hyperlane-config.md)
- Rotate secrets → [Passphrase Rotation](devops/security/03-passphrase-rotation.md)
- Debug issues → [Troubleshooting](operators/troubleshooting/01-common-issues.md)
- Submit code → [Contributing](developers/contributing/04-pull-request-process.md)

---

## Getting Help

### Documentation Issues
If you find errors or gaps in this documentation:
- File an issue: [GitHub Issues](https://github.com/kaspanet/rusty-kaspa/issues)
- Tag with `documentation` label

### Technical Support
- **Community:** [Kaspa Discord](https://discord.gg/kaspa) - `#igra-support` channel
- **Security Issues:** security@kaspa.org (do not file public issues)

### Contributing
We welcome documentation improvements! See [Contributing Guide](developers/contributing/04-pull-request-process.md).

---

## Version Information

- **Igra Version:** v0.1.0 (pre-release)
- **Kaspa Compatibility:** v0.14.0+
- **Documentation Last Updated:** 2026-02-05
- **Status:** Active development

---

## License

This documentation is licensed under MIT License.
The Igra codebase is licensed under ISC License.
