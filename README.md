 
 
 
 没有处理资源表(还没看)
 不良Tls处理(不支持tls callback)
 dll无力
 只压缩
 

 流程大概是：
 载入PE和stub.dll
 新增区段放stub的代码段（包含stub导入表和stub数据）
 使用stub的重定位表重定位一下stub
 产物使用stub的导入表
 Tls单纯搞块00，原本有的callback会丢失
 各区段原地压缩
 

 stub流程:
 解压，填充iat

 无错误检查
 密集式注解是给本人看的

 感谢看雪各种时期大牛们的资料分享
 感谢零下安全的群友们指导与帮助
 
