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

 ## Calling from Rust

Build:

go build -buildmode=c-shared -o libmpt.a witness_gen_wrapper.go 

Copy libmpt.a to rust_call/build:

cp libmpt.a rust_call/build