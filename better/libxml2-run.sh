#!/bin/bash

#start_time=`date --date='0 days ago' "+%Y-%m-%d %H:%M:%S"`

#rm libxml2_rust.txt
rm -r rewrite-workspace/libxml2_rust
# rewrite unsafe-rust in rewrite-workspace
# resolve-lifetimes不支持bitfield扩展包，需要手动对源代码进行bitfield展开
# test-inputs/test-inputs-fixer/libxml2_rust存放已展开后的代码
# cp -r test-inputs/test-inputs-fixer/libxml2_rust rewrite-workspace/
# cp -r test-inputs/libxml2_rust rewrite-workspace/
cp -r after-resolve-imports/expand_bitfield/libxml2_rust rewrite-workspace/

# cd rewrite-workspace/libxml2_rust
# cargo clean
# cargo build
# cd ../..

# 更改运行路径
# 修正resolve-lifetimes中不支持的libc类型
# 修正unsafe-fixer中不支持的let ref 和 let ref mut类型
python3 libxml2-rust1.py

# (1) resolve-imports
# export RUST_LOG=debug
# cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust` >curl-imports.txt
# save to ./after-resolve-imports
# rm -r after-resolve-imports/libxml2_rust
# cp -r rewrite-workspace/libxml2_rust after-resolve-imports/

# resolve-lifetimes不支持bitfield扩展包，需要手动对源代码进行bitfield展开
# after-resolve-imports/expand_bitfield/curl-rust存放已展开后的代码
# rm -r rewrite-workspace/libxml2_rust
# cp -r after-resolve-imports/expand_bitfield/libxml2_rust rewrite-workspace/


# (2) resolve-lifetimes
# save to after-resolve-lifetimes
# part-1
cp patch/libxml2/part1/lib.rs rewrite-workspace/libxml2_rust
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build &>/dev/null
cd ../..
echo "Running resolve-imports..."
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust` &>/dev/null
echo "Finish running resolve-imports..."
echo "Running resolve-lifetimes..."
cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/libxml2_rust` &>/dev/null
echo "Finish running resolve-lifetimes..."

# part-2
cp patch/libxml2/part2/lib.rs rewrite-workspace/libxml2_rust
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build &>/dev/null
cd ../..
echo "Running resolve-imports..."
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust` &>/dev/null
echo "Finish running resolve-imports..."
echo "Running resolve-lifetimes..."
cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/libxml2_rust` &>/dev/null
echo "Finish running resolve-lifetimes..."

# part-3
cp patch/libxml2/part3/lib.rs rewrite-workspace/libxml2_rust
cd rewrite-workspace/libxml2_rust
cargo clean
cargo build &>/dev/null
cd ../..
echo "Running resolve-imports..."
cargo run --release --bin resolve-imports -- `cat rewrite-invocations/libxml2_rust` &>/dev/null
echo "Finish running resolve-imports..."

# save to after-resolve-lifetimes
# cp patch/libxml2/part_all/lib.rs rewrite-workspace/libxml2_rust
rm -r after-resolve-lifetimes/libxml2_rust
cp -r rewrite-workspace/libxml2_rust after-resolve-lifetimes/


# (3) run unsafe-fixer
# 修正unsafe-fixer中不支持的let ref 和 let ref mut类型
python3 libxml2-rust1.py
cp patch/libxml2/part_all/lib.rs rewrite-workspace/libxml2_rust

cd ..
cd unsafe-fixer
cargo clean
cargo build --release &>/dev/null
cd ..
echo "Running unsafe-fixer..."
unsafe-fixer/target/release/unsafe-fixer better/rewrite-workspace/libxml2_rust
echo "Finish running unsafe-fixer..."

# 保存结果
cd better
rm -r result/libxml2_rust
cp -r rewrite-workspace/libxml2_rust result/

# 编译结果
cd result/libxml2_rust
cargo clean
RUSTFLAGS=-Awarnings cargo build
#finish_time=`date --date='0 days ago' "+%Y-%m-%d %H:%M:%S"`

#duration=$(($(($(date +%s -d "$finish_time")-$(date +%s -d "$start_time")))))
#touch libxmltime.txt
#echo "this shell script execution duration: $duration">libxmltime.txt
