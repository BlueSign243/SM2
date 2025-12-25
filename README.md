# SM2算法
SM2算法的C语言实现

## 项目结构
```
SM2/
├── include/                # 头文件目录
│   ├── bn.h                # 大整数运算库
│   ├── ec.h                # 椭圆曲线基础运算
│   ├── point.h             # 椭圆曲线点运算
│   ├── SM2.h               # SM2算法接口
│   └── SM3.h               # SM3哈希算法
├── src/                    # 源代码目录
│   ├── bn.c                # 大整数实现
│   ├── ec.c                # 椭圆曲线实现
│   ├── point.c             # 点运算实现
│   ├── SM2.c               # SM2算法实现
│   ├── SM3.c               # SM3哈希实现
│   └── main.c              # 示例程序
├── CMakeLists.txt          # CMake构建配置
├── README.md               # 项目说明
└── .gitignore              # Git忽略文件
```

## SM2算法接口
### SM2密钥生成
```c
int SM2_GenerateKeyPair(SM2_PRI_KEY *pri_key, SM2_PUB_KEY *pub_key, group *g);
```

### SM2签名
```c
int SM2_Sign(SM2_PRI_KEY *pri_key, group *g, const uint8_t *msg, size_t mlen,
             uint8_t *id, size_t entl, SM2_SIG *sig);
```

### SM2验签
```c
int SM2_Verify(SM2_PUB_KEY *pub_key, group *g, const uint8_t *msg, size_t mlen,
               uint8_t *id, size_t entl, const SM2_SIG *sig);
``` 

## 运行方法
使用cmake构建项目

## 运行结果
```c
Test done, success 100 / 100.
```
