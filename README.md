# MD5
MD5哈希算法的C++实现（兼容大端字节序的CPU）
# 测试代码
```
#include<iostream>
#include<iomanip>
#include"md5.c"

int main() {

	using namespace std;

	u8 $finalHash[16] = {};
	const char* str = "a";

	//调用MD5
	int ret = MD5((u8*)str, strnlen_s(str, INT_MAX), $finalHash);
	cout << ret << "\n\n";

	//输出结果
	for (int i = 0; i < 16; i++) {

		cout << hex << setw(2) << setfill('0') << int($finalHash[i]);
	}
	cout << "\n\n";

	return 0;
}

```
