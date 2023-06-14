# BiliAuth.py
模拟B站登录，获取 `access_token`, `refresh_token` 和 `cookies`

# 使用前须知

* 此脚本模拟的是哔哩哔哩 `安卓APP` 登录步骤，不保证返回的 `access_token` 与 `refresh_token` 能在其他客户端接口（如TV端，iOS端）通用

* 有任何使用问题，改进建议等，欢迎开issue讨论！

* 如果验证码识别一直提示余额不足，欢迎开issue提醒充值

# 使用方法

## 安装依赖
* Python >= 3.6<br>
```
pip install -r requirements.txt
```

## 传入账号密码
```
auth = BiliAuth()

username: str = 登录时使用的手机号

password: str = 登录使用的密码

region: str = 手机号所在的国家代码（中国为86，美国为1，等等）

auth.set(username, password, region)
```

## 账号密码登录获取 `access_token`, `refresh_token` 和 `cookies`
```
resp: dict = await auth.acquire(is_print=False, fallback_sms=False)
```

参数解析：
```
is_print: Optional[bool] = False 是否打印返回结果，默认False

fallback_sms: Optional[bool] = False 提示需要验证手机号时是否自动发送短信验证码并通过短信登录，默认False
```

## 短信验证码登录获取 access_token 和 cookies
```
resp: dict = await auth.acquire_by_sms(is_print=False)
```

参数解析：
```
is_print: Optional[bool] = False 是否打印返回结果，默认False
```
