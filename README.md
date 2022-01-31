# BiliAuth.py
模拟B站登录，获取access_key和cookies

## 使用方法
#### 1. 安装依赖
* Python >= 3.6<br>
`
pip install -r requirements.txt
`
#### 2. 传入账号密码
`
BiliAuth.set(username, password)
`<br><br>
参数解析：<br>
`username`: 登录时使用的手机号<br>
`password`: 登录使用的密码

#### 3. 实例化类
`
auth = BiliAuth()
`
#### 4. 获取access_key 和 cookies
`
resp: dict = auth.acquire()
`
