# RPC-Fuzzer
A simple Python fuzzer for testing JSON-RPC interfaces, specifically designed for Substrate-based nodes.

## Overview

Performs fuzzing on WebSocket JSON-RPC endpoints. This is **not** coverage-guided, but it follows a grammar. Particularly optimized for  Substrate/Polkadot node RPC interfaces but can be adapted for other RPC services, like Ethereum RPCs. The fuzzer generates appropriate parameter  based on parameter types, adapts its testing strategy based on successful responses, and log everything in stdout / filesystem.

## Requirements

- Python 3.6+
- websocket-client
- jq (for the generated scripts)
- wscat (for executing the generated scripts)

## Installation

```bash
git clone https://github.com/yourusername/adaptive-rpc-fuzzer.git
cd adaptive-rpc-fuzzer
pip install websocket-client
```

## Usage

```bash
python rpcfuzz.py # just modify the source code for the parameters, it fuzzes `localhost` by default
```

## Output

The fuzzer generates a `rpc_queries.sh` file containing all the RPC calls made during the campaign using `wscat`. This is useful for reproducing specific test cases.

Example of generated command:
```bash
wscat -c ws://127.0.0.1:9944 -x '{"id": 1, "jsonrpc": "2.0", "method": "chain_getBlockHash", "params": [123]}' | jq;
```

#  Trophies

RPCFuzzer found a critical DoS on a Substrate client, crashing every nodes exposing a RPC (patch not published yet)
