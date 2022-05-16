# 简述
这是一个使用 Win32 api 编写的一个 PE 文件查看器。

## 初衷
由于自身代码能力一直薄弱，所以想要通过实现一个有意思的工具来磨练自己。

之所以选择 PEView 作为目标，是受《逆向工程核心原理》的影响，其中作者使用的[PEview](https://reversecore.com/111)由于历史遗留问题（已修正，具体修正步骤可查看博客[PEView](https://www.a1ee.cn/simple/peview/)），以及对`x64`不友好的支持，促使我想要做一个更为全面的替代品。

## 技术核心
该程序使用 Win32 api 实现 GUI 界面，这是为了保证程序可独立运行且文件大小不会很大。

文件读取部分采用了 C 代码实现，PE 文件结构由 winnt.h 内置的文件数据结构体读取。

PE 文件结构的组成细则，可参考博客[PE文件格式](https://www.a1ee.cn/simple/pe%E6%96%87%E4%BB%B6%E6%A0%BC%E5%BC%8F/)。

## 不足之处
- 菜单列没有参考程序那么细致；
- 对文件结构的显示并未做到最细；
- 由于并未直接采用汇编代码编写，大小上还是比参考程序大了一倍多；

**注：**如果你在使用过程中发现了 bug 和错误，欢迎留言交流：）
