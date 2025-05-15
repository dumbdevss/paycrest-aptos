# Paycrest Aptos Contract

Paycrest is a protocol built to create fiat liquidity pools for on-ramp and off-ramp applications on the Aptos blockchain.

## Project Overview

This repository contains the smart contract code for the Paycrest protocol, implementing the core functionality for managing fiat liquidity pools that facilitate seamless on-ramp and off-ramp operations between fiat currencies and the Aptos blockchain.

## Project Structure

```
paycrest-aptos/
├── sources/
│   └── gateway.move     # Core protocol implementation
└── Move.toml           # Package dependencies and configuration
```

## Prerequisites

- [Aptos CLI](https://aptos.dev/cli-tools/aptos-cli-tool/install-aptos-cli)
- [Move Language](https://move-language.github.io/move/)
- Basic knowledge of blockchain development

## Setup and Deployment

### Initialize Account

Before you can deploy the contract, you need to initialize your Aptos account:

```bash
aptos init
```

This command will guide you through the account setup process and create necessary configuration files.

### Build the Project

To compile the Move modules:

```bash
aptos move compile
```

This command verifies the syntax and types of your Move code before generating bytecode.

### Publish the Module

To deploy the compiled modules to the Aptos blockchain:

```bash
aptos move publish
```

This will publish the module to your account on the Aptos blockchain.

## Key Features

- Fiat liquidity pool management
- On-ramp functionality for converting fiat to crypto
- Off-ramp functionality for converting crypto to fiat
- Protocol governance mechanisms
- Fee structure management

## Development

To contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for your implementations
5. Submit a pull request

## Testing

Run unit tests with:

```bash
aptos move test
```

## Contact

For questions or support, please reach out to taiwotriumphant@gmail.com