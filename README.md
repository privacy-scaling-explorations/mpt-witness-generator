# Merkle Patricia Trie witness generator

This project aims to prepare witness generator for Merkle Patricial Trie circuit which is part of
[zkevm-circuits](https://github.com/appliedzkp/zkevm-circuits).

It's based on [geth](https://github.com/ethereum/go-ethereum) and it adds MPT circuit required
info to the eth_getProof. Roughly, it takes eth_getProof output for the storage slots that are
modified in a block, and it then applies these modifications, obtains the proof after
each modification (the modifications are applied using statedb, not directly trie),
prepares witnesses out of these proofs.

<!--
What is changed compared to geth:
 * Some statedb and trie methods are made public to enable accessing internal structures.
 -->

## Generate witnesses

To generate witnesses for MPT circuit, go into witness folder and execute

```
go test gen_witnesses_from_infura_blockchain_test.go gen.go finalize.go leaf.go extension_node.go modified_extension_node.go test_tools.go branch.go util.go
```

to generate the tests that use Infura blockchain.

Execute

```
go test gen_witnesses_from_local_blockchain_test.go gen.go finalize.go leaf.go extension_node.go modified_extension_node.go test_tools.go branch.go util.go
```

to generate the tests that use a local blockchain.

The witness files will appear in generated_witnesses folder.

## Calling from Rust

Build:

```
go build -buildmode=c-archive -o libmpt.a witness_gen_wrapper.go 
```

Copy libmpt.a and libmpt.h to rust_call/build:

```
mv libmpt.* rust_call/build
```

Note: to avoid the problem described [](https://github.com/golang/go/issues/42459),
the following has been set in rust_call/.cargo/config:

```
[build]
rustflags = ["-C", "link-args=-framework CoreFoundation -framework Security"]
```
