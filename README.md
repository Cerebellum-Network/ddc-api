# ddc-api

## Prerequisites

This repository depends on shared protobuf definitions from the private [ddc-proto](https://github.com/Cerebellum-Network/ddc-proto) repository, included as a git submodule.

**First-time setup** (after cloning):

```bash
git submodule add https://github.com/Cerebellum-Network/ddc-proto.git third_party/ddc-proto
```

Or if the submodule is already registered (e.g. after pulling from a branch that has it):

```bash
git submodule update --init
```

> **Note:** You need a GitHub token with read access to `Cerebellum-Network/ddc-proto`. If using HTTPS, configure: `git config --global url."https://${GH_READ_TOKEN}@github.com/".insteadOf "https://github.com/"`

The protobuf code is generated automatically by `prost-build` during `cargo build`, using the definitions from the submodule.