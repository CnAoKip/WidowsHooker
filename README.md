# WidowsHooker
拦截电脑风险操作的神器
## 用法
调用 gt428_detours库中的EnableGlobalHook();函数开始拦截，DisableGlobalHook();停止拦截（注意：该版本不停止API Hook，会导致一些程序崩溃）
## 注意事项
请先编译并配置好微软 Detours 库，并将其静态链接到你的DLL项目中。DLL和加载DLL的程序需要严格的位数限制。
