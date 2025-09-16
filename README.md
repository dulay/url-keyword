# 关键词核查系统

## 功能简介

- 支持用户注册（需管理员审核）、登录、权限管理和IP安全防护
- 支持Excel模板下载、批量任务上传、异步多线程核查、进度实时展示
- 支持历史任务查看、结果筛选统计、结果Excel下载、分享链接
- 支持核查结果包含URL标题、HTTP状态、关键词占比、匹配详情
- 支持Docker一键部署

## 目录结构

```
keyword_checker/
│
├── app.py                 # 主Flask后端
├── requirements.txt       # Python依赖
├── Dockerfile             # Docker镜像构建文件
│
├── utils/
│   ├── crawler.py         # 爬虫与关键词比对
│   ├── excel_utils.py     # Excel工具
│   ├── user_mgmt.py       # 用户管理
│   └── security.py        # 安全与IP风控
│
├── templates/
│   ├── index.html         # 首页/任务上传
│   ├── login.html         # 登录
│   ├── register.html      # 注册
│   ├── admin.html         # 管理员审核
│   ├── tasks.html         # 历史任务
│   └── result.html        # 结果页
│
├── uploads/               # 上传临时文件
├── results/               # 任务核查结果Excel
├── tasks.csv              # 任务记录
└── users.csv              # 用户数据库
```

## 一键部署（Docker）

1. **构建镜像**
   ```sh
   docker build -t keyword_checker .
   ```
2. **启动容器**
   ```sh
   docker run -d -p 8000:8000 -v $(pwd)/uploads:/app/uploads -v $(pwd)/results:/app/results keyword_checker
   ```
3. **访问网站**
   http://localhost:8000

> 首次请注册管理员账号，然后在管理后台审核新用户。

---

## 重要说明

- 默认以`users.csv`和`tasks.csv`作为持久化数据存储，适合单机与测试环境。
- 生产环境请配置SECRET_KEY、挂载卷、HTTPS反代等更高安全措施。# url-keyword
