# 🏗️ Arsitektur Uomi Node

```mermaid
flowchart TD
    subgraph Node
      Consensus[Consensus Engine]
      Runtime[Runtime (WASM)]
      Networking[P2P Networking]
      RPC[RPC API]
    end

    User[User / CLI] --> RPC
    RPC --> Runtime
    Consensus --> Runtime
    Runtime --> Storage[(Database)]
    Networking <--> Consensus
