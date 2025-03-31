# MIS241班费管理系统

这是一个基于Python Flask的班费管理系统，用于管理班级的收支记录。

## 功能特点

- 用户登录（手机号+验证码）
- 班费支出记录管理
- 班费收入记录管理
- 学生管理
- 角色管理
- 数据导入导出

## 安装说明

1. 确保已安装Python 3.7或更高版本
2. 克隆项目到本地
3. 安装依赖包：
   ```bash
   pip install -r requirements.txt
   ```

## 运行说明

1. 在项目根目录下运行：
   ```bash
   python app.py
   ```
2. 打开浏览器访问：http://localhost:5000

## 技术栈

- 后端：Python Flask
- 前端：HTML, CSS, JavaScript, Bootstrap 5
- 数据库：SQLite

## 项目结构

```
fundKeeper/
├── app.py              # 主应用文件
├── requirements.txt    # 项目依赖
├── templates/         # HTML模板
│   ├── login.html     # 登录页面
│   └── dashboard.html # 仪表板页面
└── README.md          # 项目说明文档
``` 