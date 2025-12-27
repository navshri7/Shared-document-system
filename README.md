The project is split across a terminal client, a coordinating name server, and a pair of storage servers so you can experiment with collaborative editing workflows on a local network.

## What’s included
- **Client** (`client/`): Handles login, file browsing, sentence-level edits, and checkpoint commands over TCP.
- **Name server** (`name_server/`): Maintains the global trie index, LRU search cache, ACLs, and orchestrates replication/health checks.
- **Storage servers** (`storage_server/`): Persist file data, enforce sentence locks, serve reads/writes, and pull replicas on demand.
- **Common utilities** (`common/`): Shared protocol structs, logging helpers, and error codes.

## Getting started
- **Build everything**
```bash
make all
```
- **Spin up the components**
```bash
./nameserver 8080
./storageserver 8080 9001
./storageserver 8080 9002
./client_app 127.0.0.1 8080
```
- **Clean slate**
```bash
make clean
make clean-storage
```

## Highlights
- **Fast lookups** thanks to a trie-based index with an LRU cache for hot filenames.
- **Replication** managed by background threads that keep secondaries in sync and promote them on failure.
- **Sentence-level collaboration** that lets multiple users edit different parts of a document without clobbering each other.

## Repo tour
- **`client/`**: Interactive client loop, networking, and command parsing.
- **`name_server/`**: Registration flows, metadata management, caching, and replication logic.
- **`storage_server/`**: File I/O, checkpoint utilities, and sentence-level locking.
- **`common/`**: Cross-component protocol definitions and utilities.

## Assumptions and Implementation Details

- If WRITE access is suddenly revoked while another user is writing, the final change IS committed, but after that won't be able to write.
- WRITE sentence index and word index starts from 0.
- All bonus subparts are implemented
- There is retransmission for SS failures, and appropriate error meddages when everything fails/goes down. 
- The Trie data structure with an O(1) cache is used for lookups for files and access control
- Extra feature implemented: File edit history