# BiliAuth.py
模拟B站登录，获取access_token, refresh_token和cookies

## 使用方法
#### 1. 安装依赖
* Python >= 3.6<br>
`
pip install -r requirements.txt
`
#### 2. 传入账号密码
`
auth = BiliAuth()
`<br>
`
auth.set(username, password)
`<br><br>
参数解析：<br>
`username: str` = 登录时使用的手机号<br>
`password: str` = 登录使用的密码

#### 4. 账号密码登录获取 access_token 和 cookies
`
resp: dict = await auth.acquire(is_print=False, fallback_sms=False)
`<br><br>
参数解析：<br>
`is_print: Optional[bool] = False` = 是否打印返回结果，默认False<br>
`fallback_sms: Optional[bool] = False` = 提示需要验证手机号时是否自动发送短信验证码并通过短信登录，默认False

#### 5. 短信验证码登录获取 access_token 和 cookies
`
resp: dict = await auth.acquire_by_sms()
`<br><br>
参数解析：<br>
`is_print: Optional[bool] = False` = 是否打印返回结果，默认False<br>
