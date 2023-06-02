#!/bin/bash

rm curl-rust.txt
rm -r rewrite-workspace/curl-rust
# rewrite unsafe-rust in rewrite-workspace
cp -r test-inputs/curl-rust rewrite-workspace/
cd rewrite-workspace/curl-rust
cargo clean
cargo build
cd ../..

# 更改运行路径
# 修正resolve-lifetimes中不支持的libc类型
# 修正unsafe-fixer中不支持的let ref 和 let ref mut类型
python3 curl-rust.py

# (1) resolve-imports
# export RUST_LOG=debug
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/curl-rust` >curl-imports.txt
# save to ./after-resolve-imports
rm -r after-resolve-imports/curl-rust
cp -r rewrite-workspace/curl-rust after-resolve-imports/

# resolve-lifetimes不支持bitfield扩展包，需要手动对源代码进行bitfield展开
# after-resolve-imports/expand_bitfield/curl-rust存放已展开后的代码
rm -r rewrite-workspace/curl-rust
cp -r after-resolve-imports/expand_bitfield/curl-rust rewrite-workspace/
cd rewrite-workspace/curl-rust
cargo clean
cargo build
cd ../..

# (2) resolve-lifetimes
# save to after-resolve-lifetimes
# export RUST_LOG=debug
cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/curl-rust` >> curl-rust.txt
# save to after-resolve-lifetimes
rm -r after-resolve-lifetimes/curl-rust
cp -r rewrite-workspace/curl-rust after-resolve-lifetimes/

# (3) run unsafe-fixer
cd ..
cd unsafe-fixer
cargo clean
cargo build --release
cd ..
unsafe-fixer/target/release/unsafe-fixer better/rewrite-workspace/curl-rust
# 保存结果
cd better
rm -r result/curl-rust
cp -r rewrite-workspace/curl-rust result/