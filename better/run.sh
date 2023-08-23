#!/bin/bash
# start_time=`date --date='0 days ago' "+%Y-%m-%d %H:%M:%S"`

#rm $1.txt
rm -r rewrite-workspace/$1
# rewrite unsafe-rust in rewrite-workspace
cp -r test-inputs/$1 rewrite-workspace/
cd rewrite-workspace/$1
cargo clean
cargo build &>/dev/null
cd ../..

# 更改运行路径

# 修正resolve-lifetimes中不支持的libc类型
python3 run.py $1

# (1) run resolve-imports
echo "Running resolve-imports..."
RUST_BACKTRACE=1 cargo run --release --bin resolve-imports -- `cat rewrite-invocations/$1` &>/dev/null
echo "Finish running resolve-imports..."
# save to ./after-resolve-imports
rm -r after-resolve-imports/$1
cp -r rewrite-workspace/$1 after-resolve-imports/

# (2) run resolve-lifetimes
echo "Running resolve-lifetimes..."
RUST_BACKTRACE=1 cargo run --release --bin resolve-lifetimes -- -f --merge-field-lifetimes `cat rewrite-invocations/$1` &>/dev/null
echo "Finish running resolve-lifetimes..."
# save to after-resolve-lifetimes
rm -r after-resolve-lifetimes/$1
cp -r rewrite-workspace/$1 after-resolve-lifetimes/

# 修正unsafe-fixer中不支持的let ref 和 let ref mut类型
python3 run.py $1    #
# (3) run unsafe-fixer
cd ..
cd unsafe-fixer
cargo clean
cargo build --release &>/dev/null
cd ..
echo "Running unsafe-fixer..."
unsafe-fixer/target/release/unsafe-fixer better/rewrite-workspace/$1
echo "Finish running unsafe-fixer..."
# 保存结果
cd better
rm -r result/$1
cp -r rewrite-workspace/$1 result/

# 编译结果
cd result/$1
cargo clean
cargo build


#finish_time=`date --date='0 days ago' "+%Y-%m-%d %H:%M:%S"`

#duration=$(($(($(date +%s -d "$finish_time")-$(date +%s -d "$start_time")))))

#rm -f jsontime.txt
#touch jsontime.txt 
#echo "this shell script execution duration: $duration" > jsontime.txt
