# Self-tallying election voting system

## Install & run
Prerequisites:
- npm

```bash
# Install Truffle globally
npm install -g truffle

# Install Ganache globally
npm install -g ganache-cli

# Run Ganache (in a separate terminal)
ganache-cli

# Compile the contracts
truffle compile

# Migrate the contracts
truffle migrate

# To perform an example election
truffle exec scripts/interact.js
```