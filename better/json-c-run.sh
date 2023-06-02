#!/bin/bash

rm jsonc_rust.txt
rm -r rewrite-workspace/jsonc_rust
# rewrite unsafe-rust in rewrite-workspace
cp -r test-inputs/jsonc_rust rewrite-workspace/
cd rewrite-workspace/jsonc_rust
cargo clean
cargo build
cd ../..

# 更改运行路径
# 修正resolve-lifetimes中不支持的libc类型
# 修正unsafe-fixer中不支持的let ref 和 let ref mut类型
python3 json-c-rust.py

# (1) run resolve-imports
# export RUST_LOG=debug
RUST_BACKTRACE=1 cargo run --release --bin resolve-imports -- `cat rewrite-invocations/jsonc_rust` > jsonc_rust.txt
# save to ./after-resolve-imports
rm -r after-resolve-imports/jsonc_rust
cp -r rewrite-workspace/jsonc_rust after-resolve-imports/

# (2) run resolve-lifetimes
# export RUST_LOG=debug
RUST_BACKTRACE=1 cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/jsonc_rust` > jsonc_rust.txt
# save to after-resolve-lifetimes
rm -r after-resolve-lifetimes/jsonc_rust
cp -r rewrite-workspace/jsonc_rust after-resolve-lifetimes/


# (3) run unsafe-fixer
cd ..
cd unsafe-fixer
cargo clean
cargo build --release
cd ..
unsafe-fixer/target/release/unsafe-fixer better/rewrite-workspace/jsonc_rust
# 保存结果
cd better
rm -r result/jsonc_rust
cp -r rewrite-workspace/jsonc_rust result/

