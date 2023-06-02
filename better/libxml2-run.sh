#!/bin/bash

rm libxml2_rust.txt
rm -r rewrite-workspace/libxml2_rust
# rewrite unsafe-rust in rewrite-workspace
cp -r test-inputs/libxml2_rust rewrite-workspace/
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build
cd ../..

# 更改运行路径
# 修正resolve-lifetimes中不支持的libc类型
# 修正unsafe-fixer中不支持的let ref 和 let ref mut类型
python3 libxml2_rust1.py

# (1) resolve-imports
# export RUST_LOG=debug
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust` >curl-imports.txt
# save to ./after-resolve-imports
rm -r after-resolve-imports/libxml2_rust
cp -r rewrite-workspace/libxml2_rust after-resolve-imports/

# resolve-lifetimes不支持bitfield扩展包，需要手动对源代码进行bitfield展开
# after-resolve-imports/expand_bitfield/curl-rust存放已展开后的代码
rm -r rewrite-workspace/libxml2_rust
cp -r after-resolve-imports/expand_bitfield/libxml2_rust rewrite-workspace/


# (2) resolve-lifetimes
# save to after-resolve-lifetimes
# part-1
cp patch/libxml2/part1/lib.rs rewrite-workspace/libxml2_rust
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build
cd ../..
# export RUST_LOG=debug
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust`
cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/libxml2_rust`
# part-2
cp patch/libxml2/part2/lib.rs rewrite-workspace/libxml2_rust
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build
cd ../..
# export RUST_LOG=debug
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust`
cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/libxml2_rust`
# part-3
cp patch/libxml2/part3/lib.rs rewrite-workspace/libxml2_rust
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build
cd ../..
# export RUST_LOG=debug
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust`

# save to after-resolve-lifetimes
rm -r after-resolve-lifetimes/libxml2_rust
cp -r rewrite-workspace/libxml2_rust after-resolve-lifetimes/


# (3) run unsafe-fixer
python3 libxml2_rust2.py
cd ..
cd unsafe-fixer
cargo clean
cargo build --release
cd ..
unsafe-fixer/target/release/unsafe-fixer better/rewrite-workspace/libxml2_rust
# 保存结果
cd better
rm -r result/libxml2_rust
cp -r rewrite-workspace/libxml2_rust result/
