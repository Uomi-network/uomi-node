# Changelog for v0.3.3

## Changes
- fix: new release
- refactor: update block number for Turing testnet and improve offence reporting logging
- refactor: uncomment offence slashing event logic in TSS and engine pallets
- refactor: comment out offence reporting logic in TSS and engine pallets
- fix: Removes forced non-empty output workaround. Drops logic that ensured output data was at least 1 byte, as it conflicts with the updated slashing mechanism.

