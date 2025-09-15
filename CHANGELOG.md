# Changelog for v0.3.1

## Changes
- feat: new release
- refactor: comment out timestamp validation logic in message verification
- refactor: extract exclude list building logic into a separate function for clarity and reuse
- refactor: streamline validator exclusion logic in OPoC request reassignment
- refactor: conditionally check AI service status for authority nodes only
- refactor: simplify AI service version check logic for authority nodes
- feat: implement base path configuration for TSS storage and enhance directory validation
- refactor: comment out timestamp validation and message expiration logic in TSS validator
- fix: update multi-party-ecdsa dependency version to 0.1.3
- refactor: remove fallback queue for online signing requests and related tests
- feat: new smart contract addresses
- fix: enhance ECDSA signing session management by queuing online requests until offline material is available
- fix: implement gas estimation request structure and refactor gas estimation logic
- fix: enhance gas estimation logging by including default values for missing fields
- fix: add logging for gas estimation requests in MultiChainRpcClient
- fix: remove early return for empty requests in transaction signing process
- fix: improve participant index construction by using validator IDs or fallback to sequential indices
- fix: handle empty requests by setting max_request_id to last_id_u256
- fix: enable gas limit estimation for transactions when not provided
- fix: comment out incorrect year_zero balance calculation for clarity
- fix: update RPC URLs for supported chains in MultiChainRpcClient
- chore: change log level from info to debug for RPC transaction and gas estimation logs
- chore: change log level from info to debug for RPC calls and responses
- chore: streamline error handling and improve logging verbosity in output processing

