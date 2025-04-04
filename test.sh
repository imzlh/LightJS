#!/bin/sh

if [ -z "$1" ]; then
    echo "Usage: $0 <test name>"
    echo "All available tests:"
    
    # c 结尾的文件
    for i in `ls test/*.c`; do
        echo `$0 $i`
    done

    # js 结尾的文件
    for i in `ls test/*.js`; do
        # index.js 跳过
        if [ "$i" = "test/index.js" ]; then
            continue
        fi

        echo `$0 $i`
    done

    exit 1
fi

# 设置编译器，默认为gcc
CC=${CC:-gcc}

# 定义源文件和目标文件名
cd test
if [ -e "$1.c" ]
then
    TYPE="c"
else
    TYPE="js"
fi

if [ $TYPE = "c" ]
then
    # BINARY_FILE为随机数
    BINARY_FILE=$(echo $RANDOM | md5sum | head -c 10)

    # 编译命令
    $CC -o $BINARY_FILE "$1.c" ../libljs.a -ggdb -O0

    # 检查编译是否成功
    if [ $? -ne 0 ]; then
        echo "Compile failed."
        exit 1
    fi
    
    echo -e "\n\nRunning test $1..."

    # 执行生成的二进制文件
    ./$BINARY_FILE

    # 删除生成的二进制文件
    if [ "$2" != 'keep' ]
    then
        rm $BINARY_FILE -f
    fi
else
    # 执行 js 文件
    ../ljs index.js $1
fi

# 检查执行是否成功
if [ $? -ne 0 ]; then
  echo -e "\n\nERROR! The test failed."
  exit 1
fi

# 如果执行成功
echo -e "\n\nTest passed."
