from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import pandas as pd
from werkzeug.utils import secure_filename
import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import pandas as pd
from werkzeug.utils import secure_filename
from io import BytesIO  # 添加这行导入
from functools import wraps
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fundkeeper.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Permissions:
    EXPENSE_VIEW = 'expense:view'
    EXPENSE_EDIT = 'expense:edit'


    INCOME_VIEW = 'income:view'
    INCOME_EDIT = 'income:edit'


    STUDENT_VIEW = 'student:view'
    STUDENT_EDIT = 'student:edit'


    ROLE_VIEW = 'role:view'
    ROLE_EDIT = 'role:edit'


    # 角色权限映射
    ROLE_PERMISSIONS = {
        '学生': [
            EXPENSE_VIEW,
            INCOME_VIEW,
            STUDENT_VIEW,
        ],
        '财务委员': [
            EXPENSE_VIEW, EXPENSE_EDIT,
            INCOME_VIEW, INCOME_EDIT, STUDENT_VIEW
        ],
        '班长': [
            EXPENSE_VIEW,
            INCOME_VIEW,
            STUDENT_VIEW, STUDENT_EDIT
        ],
        '副班长': [
            EXPENSE_VIEW,
            INCOME_VIEW,
            STUDENT_VIEW, STUDENT_EDIT
        ],
        '管理员': [
            EXPENSE_VIEW,  EXPENSE_EDIT,
            INCOME_VIEW, INCOME_EDIT,
            STUDENT_VIEW, STUDENT_EDIT,
            ROLE_VIEW, ROLE_EDIT
        ]
    }


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    role_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    permissions = db.Column(db.Text, nullable=False)  # 存储为JSON字符串
    status = db.Column(db.String(10), nullable=False, default='启用')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'role_no': self.role_no,
            'name': self.name,
            'permissions': self.permissions,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    @property
    def permission_list(self):
        return json.loads(self.permissions) if self.permissions else []

    def has_permission(self, permission):
        return permission in self.permission_list


# 学生模型
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_no = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='启用')
    password_hash = db.Column(db.String(120), nullable=False, default='123456')  # 添加密码字段
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Flask-Login required attributes
    is_active = True
    is_authenticated = True
    is_anonymous = False

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'student_no': self.student_no,
            'name': self.name,
            'phone': self.phone,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# 支出模型
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_no = db.Column(db.String(20), unique=True, nullable=False)  # 支出编号
    user = db.Column(db.String(80), nullable=False)  # 使用人
    type = db.Column(db.String(50), nullable=False)  # 使用类型
    amount = db.Column(db.Float, nullable=False)  # 使用额度
    purpose = db.Column(db.String(200))  # 用途
    date = db.Column(db.Date, nullable=False)  # 使用日期
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @property
    def created_at_datetime(self):
        if isinstance(self.created_at, (int, float)):
            return datetime.fromtimestamp(float(self.created_at)/1000)
        return self.created_at

    @staticmethod
    def generate_expense_no(date):
        # 确保date是datetime对象
        if isinstance(date, str):
            date = datetime.strptime(date, '%Y-%m-%d')
        elif isinstance(date, (int, float)):
            date = datetime.fromtimestamp(float(date)/1000)
        
        date_str = date.strftime('%Y%m%d')
        # 获取指定日期的最大编号
        last_expense = Expense.query.filter(
            Expense.expense_no.like(f'{date_str}%')
        ).order_by(Expense.expense_no.desc()).first()

        if last_expense:
            last_number = int(last_expense.expense_no[-3:])
            new_number = last_number + 1
        else:
            new_number = 1

        return f'{date_str}{new_number:03d}'

    @property
    def date_str(self):
        if isinstance(self.date, (int, float)):
            return datetime.fromtimestamp(float(self.date)/1000).strftime('%Y-%m-%d')
        elif isinstance(self.date, str):
            return self.date
        elif isinstance(self.date, datetime):
            return self.date.strftime('%Y-%m-%d')
        return str(self.date)

    def __init__(self, **kwargs):
        # 确保日期格式正确
        if 'date' in kwargs:
            date_value = kwargs['date']
            if isinstance(date_value, (int, float)) or (isinstance(date_value, str) and date_value.isdigit()):
                # 如果是时间戳（毫秒）
                kwargs['date'] = datetime.fromtimestamp(float(date_value)/1000).date()
            elif isinstance(date_value, str):
                # 如果是日期字符串
                kwargs['date'] = datetime.strptime(date_value, '%Y-%m-%d').date()
            elif isinstance(date_value, datetime):
                # 如果是datetime对象
                kwargs['date'] = date_value.date()
        
        # 确保created_at被设置
        if 'created_at' not in kwargs:
            kwargs['created_at'] = datetime.utcnow()
        elif isinstance(kwargs['created_at'], (int, float)):
            # 如果是时间戳，转换为datetime
            kwargs['created_at'] = datetime.fromtimestamp(float(kwargs['created_at'])/1000)
        
        super(Expense, self).__init__(**kwargs)
        if not self.expense_no:
            self.expense_no = self.generate_expense_no(self.date)


# 收入记录模型
class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    income_no = db.Column(db.String(20), unique=True, nullable=False)  # 收入编号
    user = db.Column(db.String(50), nullable=False)  # 缴纳人
    amount = db.Column(db.Float, nullable=False)  # 缴纳额度
    date = db.Column(db.Date, nullable=False)  # 缴纳日期

    def __repr__(self):
        return f'<Income {self.income_no}>'


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'success': False, 'message': '请先登录'}), 401

            user_role = Role.query.filter_by(name=current_user.role).first()
            if not user_role or not user_role.has_permission(permission):
                return jsonify({'success': False, 'message': '权限不足'}), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def check_permission(permission):
    if not current_user.is_authenticated:
        return False

    user_role = Role.query.filter_by(name=current_user.role).first()
    return user_role and user_role.has_permission(permission)

@app.route('/roles')
@login_required
def roles():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    name = request.args.get('name', '')
    status = request.args.get('status', '')

    query = Role.query

    if name:
        query = query.filter(Role.name.like(f'%{name}%'))
    if status:
        query = query.filter(Role.status == status)

    pagination = query.order_by(Role.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    roles = pagination.items

    return render_template('roles.html', roles=roles, pagination=pagination)


@app.route('/api/roles', methods=['POST'])
@login_required
@permission_required(Permissions.ROLE_EDIT)
def create_role():
    if not check_permission(Permissions.ROLE_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        name = request.form.get('name')
        permissions = request.form.get('permissions')
        status = request.form.get('status', '启用')

        if not name or not permissions:
            return jsonify({'success': False, 'message': '角色名称和权限不能为空'})

        # 生成角色编号
        role_no = f'R{datetime.now().strftime("%Y%m%d%H%M%S")}'

        role = Role(
            role_no=role_no,
            name=name,
            permissions=permissions,
            status=status
        )

        db.session.add(role)
        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/roles/<int:id>', methods=['PUT'])
@login_required
@permission_required(Permissions.ROLE_EDIT)
def update_role(id):
    if not check_permission(Permissions.ROLE_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        role = Role.query.get_or_404(id)

        role.name = request.form.get('name', role.name)
        role.permissions = request.form.get('permissions', role.permissions)
        role.status = request.form.get('status', role.status)

        db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/roles/<int:id>', methods=['DELETE'])
@login_required
@permission_required(Permissions.ROLE_EDIT)
def delete_role(id):
    if not check_permission(Permissions.ROLE_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        role = Role.query.get_or_404(id)
        db.session.delete(role)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


def create_test_roles():
    if not Role.query.first():
        roles = [
            Role(
                role_no='R202401010001',
                name='管理员',
                permissions=json.dumps(Permissions.ROLE_PERMISSIONS['管理员']),
                status='启用'
            ),
            Role(
                role_no='R202401010002',
                name='班长',
                permissions=json.dumps(Permissions.ROLE_PERMISSIONS['班长']),
                status='启用'
            ),
            Role(
                role_no='R202401010003',
                name='副班长',
                permissions=json.dumps(Permissions.ROLE_PERMISSIONS['副班长']),
                status='启用'
            ),
            Role(
                role_no='R202401010004',
                name='财务委员',
                permissions=json.dumps(Permissions.ROLE_PERMISSIONS['财务委员']),
                status='启用'
            ),
            Role(
                role_no='R202401010005',
                name='学生',
                permissions=json.dumps(Permissions.ROLE_PERMISSIONS['学生']),
                status='启用'
            )
        ]
        db.session.add_all(roles)
        db.session.commit()

# 学生管理页面路由
@app.route('/students')
@login_required
def students():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # 构建查询
    query = Student.query.filter(Student.role != '管理员')  # 排除管理员角色

    # 应用过滤条件
    name = request.args.get('name', '')
    if name:
        query = query.filter(Student.name.like(f'%{name}%'))

    role = request.args.get('role', '')
    if role:
        query = query.filter(Student.role == role)

    status = request.args.get('status', '')
    if status:
        query = query.filter(Student.status == status)

    # 执行分页查询
    pagination = query.order_by(Student.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)

    return render_template('students.html', students=pagination.items, pagination=pagination)

@app.route('/api/students', methods=['POST'])
@login_required
@permission_required(Permissions.STUDENT_EDIT)
def create_student():
    if not check_permission(Permissions.STUDENT_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        data = request.form
        student = Student(
            student_no=data['student_no'],
            name=data['name'],
            phone=data['phone'],
            email=data['email'],
            role=data['role'],
            status=data['status']
        )
        db.session.add(student)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# 更新学生API
@app.route('/api/students/<int:id>', methods=['PUT'])
@login_required
@permission_required(Permissions.STUDENT_EDIT)
def update_student(id):
    if not check_permission(Permissions.STUDENT_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        student = Student.query.get_or_404(id)
        data = request.form
        student.student_no = data['student_no']
        student.name = data['name']
        student.phone = data['phone']
        student.email = data['email']
        student.role = data['role']
        student.status = data['status']
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/students/<int:id>', methods=['DELETE'])
@login_required
@permission_required(Permissions.STUDENT_EDIT)
def delete_student(id):
    if not check_permission(Permissions.STUDENT_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        student = Student.query.get_or_404(id)
        db.session.delete(student)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


# # 添加学生API
# @app.route('/api/students', methods=['POST'])
# def add_student():
#     try:
#         data = request.form
#         student = Student(
#             student_no=data['student_no'],
#             name=data['name'],
#             class_name=data['class_name'],
#             phone=data.get('phone'),
#             email=data.get('email')
#         )
#         db.session.add(student)
#         db.session.commit()
#         return jsonify({'success': True})
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'success': False, 'message': str(e)})


# # 批量导入学生API
# @app.route('/api/students/import', methods=['POST'])
# def import_students():
#     try:
#         if 'file' not in request.files:
#             return jsonify({'success': False, 'message': '没有上传文件'})
#
#         file = request.files['file']
#         if file.filename == '':
#             return jsonify({'success': False, 'message': '没有选择文件'})
#
#         if not file.filename.endswith(('.xlsx', '.xls')):
#             return jsonify({'success': False, 'message': '只支持 .xlsx 和 .xls 格式的文件'})
#
#         # 读取Excel文件
#         df = pd.read_excel(file)
#
#         # 验证必要的列是否存在
#         required_columns = ['学号', '姓名', '班级']
#         if not all(col in df.columns for col in required_columns):
#             return jsonify({'success': False, 'message': '文件格式不正确，请使用正确的模板'})
#
#         # 导入数据
#         for _, row in df.iterrows():
#             student = Student(
#                 student_no=str(row['学号']),
#                 name=row['姓名'],
#                 class_name=row['班级'],
#                 phone=str(row.get('联系电话', '')),
#                 email=str(row.get('邮箱', ''))
#             )
#             db.session.add(student)
#
#         db.session.commit()
#         return jsonify({'success': True})
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'success': False, 'message': str(e)})


# 下载学生导入模板

# @app.route('/api/students/template')
# def download_student_template():
#     # 创建示例数据
#     data = {
#         '学号': ['2021001', '2021002'],
#         '姓名': ['张三', '李四'],
#         '班级': ['计算机1班', '计算机1班'],
#         '联系电话': ['13800138000', '13800138001'],
#         '邮箱': ['zhangsan@example.com', 'lisi@example.com']
#     }
#     df = pd.DataFrame(data)
#
#     # 创建Excel文件
#     output = BytesIO()
#     with pd.ExcelWriter(output, engine='openpyxl') as writer:
#         df.to_excel(writer, index=False)
#     output.seek(0)
#
#     return send_file(
#         output,
#         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
#         as_attachment=True,
#         download_name='student_template.xlsx'
#     )


# 创建测试学生数据
def create_test_students():
    if not Student.query.first():
        test_students = [
            Student(
                student_no='20240001',
                name='张三',
                phone='13800138000',
                email='zhangsan@example.com',
                role='学生',
                status='启用'
            ),
            Student(
                student_no='20240002',
                name='李四',
                phone='13800138001',
                email='lisi@example.com',
                role='班长',
                status='启用'
            ),
            Student(
                student_no='20240003',
                name='王五',
                phone='13800138002',
                email='wangwu@example.com',
                role='副班长',
                status='启用'
            ),
            Student(
                student_no='20240004',
                name='林六',
                phone='13800138003',
                email='lingliu@example.com',
                role='管理员',
                status='启用'
            )
        ]
        for student in test_students:
            student.set_password('123456')  # 设置初始密码
            db.session.add(student)
        db.session.commit()

# 收入记录相关路由
@app.route('/income')
@login_required
def income():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # 构建查询
    query = Income.query

    # 添加搜索条件
    user = request.args.get('user')
    if user:
        query = query.filter(Income.user.like(f'%{user}%'))

    date = request.args.get('date')
    if date:
        query = query.filter(Income.date == datetime.strptime(date, '%Y-%m-%d').date())

    # 按日期降序排序
    query = query.order_by(Income.date.desc())

    # 分页
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    incomes = pagination.items

    return render_template('income.html', incomes=incomes, pagination=pagination)


# 新增收入记录
@app.route('/api/income', methods=['POST'])
@login_required
@permission_required(Permissions.INCOME_EDIT)
def add_income():
    if not check_permission(Permissions.INCOME_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        user = request.form.get('user')
        amount = float(request.form.get('amount'))
        date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()

        # 生成收入编号
        today = date.strftime('%Y%m%d')
        count = Income.query.filter(Income.date == date).count() + 1
        income_no = f"{today}{count:03d}"

        income = Income(
            income_no=income_no,
            user=user,
            amount=amount,
            date=date
        )

        db.session.add(income)
        db.session.commit()

        return jsonify({'success': True, 'message': '收入记录添加成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'添加失败：{str(e)}'})


# 更新收入记录
@app.route('/api/income/<int:id>', methods=['PUT'])
@login_required
@permission_required(Permissions.INCOME_EDIT)
def update_income(id):
    if not check_permission(Permissions.INCOME_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        income = Income.query.get_or_404(id)

        income.user = request.form.get('user')
        income.amount = float(request.form.get('amount'))
        income.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()

        db.session.commit()
        return jsonify({'success': True, 'message': '收入记录更新成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'更新失败：{str(e)}'})


# 删除收入记录
@app.route('/api/income/<int:id>', methods=['DELETE'])
@login_required
@permission_required(Permissions.INCOME_EDIT)
def delete_income(id):
    if not check_permission(Permissions.INCOME_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        income = Income.query.get_or_404(id)
        db.session.delete(income)
        db.session.commit()
        return jsonify({'success': True, 'message': '收入记录删除成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'删除失败：{str(e)}'})


# 批量导入收入记录
@app.route('/api/income/import', methods=['POST'])
@login_required
@permission_required(Permissions.INCOME_EDIT)
def import_income():
    if not check_permission(Permissions.INCOME_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': '没有上传文件'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': '没有选择文件'})

        if not file.filename.endswith(('.xlsx', '.xls')):
            return jsonify({'success': False, 'message': '不支持的文件格式'})

        # 读取Excel文件
        df = pd.read_excel(file)

        # 验证数据格式
        required_columns = ['缴纳人', '缴纳额度', '缴纳日期']
        if not all(col in df.columns for col in required_columns):
            return jsonify({'success': False, 'message': '文件格式不正确，请使用模板文件'})

        # 处理数据
        for _, row in df.iterrows():
            try:
                # 生成收入编号
                date = pd.to_datetime(row['缴纳日期']).date()
                today = date.strftime('%Y%m%d')
                count = Income.query.filter(Income.date == date).count() + 1
                income_no = f"{today}{count:03d}"

                income = Income(
                    income_no=income_no,
                    user=str(row['缴纳人']),
                    amount=float(row['缴纳额度']),
                    date=date
                )
                db.session.add(income)
            except Exception as e:
                db.session.rollback()
                return jsonify({'success': False, 'message': f'数据导入失败：{str(e)}'})

        db.session.commit()
        return jsonify({'success': True, 'message': '数据导入成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'导入失败：{str(e)}'})


# 下载导入模板
@app.route('/api/income/template')
@login_required
@permission_required(Permissions.INCOME_EDIT)
def download_income_template():
    if not check_permission(Permissions.INCOME_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        # 创建示例数据
        data = {
            '缴纳人': ['张三', '李四'],
            '缴纳额度': [100.00, 200.00],
            '缴纳日期': [datetime.now().date(), datetime.now().date()]
        }
        df = pd.DataFrame(data)

        # 保存为Excel文件
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='收入记录')

        output.seek(0)
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='income_template.xlsx'
        )
    except Exception as e:
        return jsonify({'success': False, 'message': f'模板下载失败：{str(e)}'})



# 创建测试数据
def create_test_incomes():
    # 检查是否已存在测试数据
    if Income.query.first() is not None:
        return

    # 创建测试数据
    test_incomes = [
        {
            'income_no': '20240115001',
            'user': '张三',
            'amount': 100.00,
            'date': datetime(2024, 1, 15).date()
        },
        {
            'income_no': '20240115002',
            'user': '李四',
            'amount': 200.00,
            'date': datetime(2024, 1, 15).date()
        },
        {
            'income_no': '20240116001',
            'user': '王五',
            'amount': 150.00,
            'date': datetime(2024, 1, 16).date()
        }
    ]

    for income_data in test_incomes:
        income = Income(**income_data)
        db.session.add(income)

    db.session.commit()



@login_manager.user_loader
def load_user(user_id):
    return Student.query.get(int(user_id))


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form.get('phone')
        password = request.form.get('password')

        # 查找学生
        student = Student.query.filter_by(phone=phone).first()
        if student and student.check_password(password):
            # 直接使用学生对象登录
            login_user(student)
            return redirect(url_for('expenses'))
        else:
            flash('手机号或密码错误')
    return render_template('login.html')


@app.route('/send_verification_code', methods=['POST'])
def send_verification_code():
    phone = request.form.get('phone')
    if not phone or len(phone) != 11:
        return jsonify({'success': False, 'message': '请输入正确的手机号'})
    return jsonify({'success': True, 'message': '验证码已发送'})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/expenses')
@login_required
def expenses():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # 获取筛选条件
    user = request.args.get('user', '')
    type = request.args.get('type', '')
    date = request.args.get('date', '')

    # 构建查询
    query = Expense.query

    if user:
        query = query.filter(Expense.user.like(f'%{user}%'))
    if type:
        query = query.filter(Expense.type == type)
    if date:
        try:
            # 尝试解析日期字符串
            if isinstance(date, (int, float)) or (isinstance(date, str) and date.isdigit()):
                # 如果是时间戳（毫秒）
                date_obj = datetime.fromtimestamp(float(date)/1000).date()
            else:
                # 如果是日期字符串
                date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            query = query.filter(Expense.date == date_obj)
        except (ValueError, TypeError):
            pass  # 如果日期解析失败，忽略日期过滤

    # 获取当前日期和6个月前的日期
    today = datetime.now()
    six_months_ago = today.replace(day=1)  # 设置为当月1号
    for _ in range(6):
        if six_months_ago.month == 1:
            six_months_ago = six_months_ago.replace(year=six_months_ago.year - 1, month=12)
        else:
            six_months_ago = six_months_ago.replace(month=six_months_ago.month - 1)

    # 获取最早的记录日期
    earliest_date = db.session.query(
        db.func.min(db.func.date(Expense.date))
    ).scalar()
    earliest_income_date = db.session.query(
        db.func.min(db.func.date(Income.date))
    ).scalar()
    
    if earliest_income_date and earliest_date:
        start_date = min(earliest_date, earliest_income_date)
    elif earliest_income_date:
        start_date = earliest_income_date
    elif earliest_date:
        start_date = earliest_date
    else:
        start_date = six_months_ago.date()

    # 添加日期范围过滤
    query = query.filter(Expense.date >= start_date)

    print(f"Date range filter: from {start_date} to {today.date()}")  # 调试信息

    # 获取分页数据
    try:
        # 获取所有记录
        all_expenses = query.all()
        print(f"Found {len(all_expenses)} expenses")  # 调试信息
        
        # 按日期排序（使用date_str属性）
        sorted_expenses = sorted(all_expenses, key=lambda x: x.date_str, reverse=True)
        # 手动进行分页
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        expenses = sorted_expenses[start_idx:end_idx]
        
        print(f"Displaying expenses from index {start_idx} to {end_idx}")  # 调试信息
        for expense in expenses:
            print(f"Expense: {expense.expense_no}, Date: {expense.date_str}")  # 调试信息
            
        total = len(all_expenses)
        total_pages = (total + per_page - 1) // per_page
        
        # 创建分页对象
        class Pagination:
            def __init__(self, items, page, per_page, total, pages):
                self.items = items
                self.page = page
                self.per_page = per_page
                self.total = total
                self.pages = pages
                self.has_prev = page > 1
                self.has_next = page < pages
                self.prev_num = page - 1
                self.next_num = page + 1

            def iter_pages(self):
                return range(1, self.pages + 1)

        pagination = Pagination(
            items=expenses,
            page=page,
            per_page=per_page,
            total=total,
            pages=total_pages
        )
    except Exception as e:
        print(f"Error in pagination: {str(e)}")  # 调试信息
        # 如果排序出错，尝试不带排序的分页
        all_expenses = query.all()
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        expenses = all_expenses[start_idx:end_idx]
        total = len(all_expenses)
        total_pages = (total + per_page - 1) // per_page
        
        pagination = Pagination(
            items=expenses,
            page=page,
            per_page=per_page,
            total=total,
            pages=total_pages
        )

    # 获取支出统计数据
    expense_monthly_data = db.session.query(
        db.func.strftime('%Y-%m', Expense.date).label('month'),
        db.func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= start_date
    ).group_by('month').order_by('month').all()

    expense_type_data = db.session.query(
        Expense.type,
        db.func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= start_date
    ).group_by(Expense.type).all()

    # 获取收入统计数据
    income_monthly_data = db.session.query(
        db.func.strftime('%Y-%m', Income.date).label('month'),
        db.func.sum(Income.amount).label('total')
    ).filter(
        Income.date >= start_date
    ).group_by('month').order_by('month').all()

    # 获取所有历史数据用于计算累计净额
    all_expenses = db.session.query(
        db.func.strftime('%Y-%m', Expense.date).label('month'),
        db.func.sum(Expense.amount).label('total')
    ).group_by('month').order_by('month').all()

    all_incomes = db.session.query(
        db.func.strftime('%Y-%m', Income.date).label('month'),
        db.func.sum(Income.amount).label('total')
    ).group_by('month').order_by('month').all()

    # 创建完整的月度数据，确保所有月份都有值
    complete_expense_data = []
    complete_income_data = []
    complete_net_data = []

    # 创建月份到金额的映射
    expense_map = {month: total for month, total in all_expenses}
    income_map = {month: total for month, total in all_incomes}

    # 计算累计净额（使用所有历史数据）
    cumulative_net = 0
    all_months = set()
    for month, _ in all_expenses:
        all_months.add(month)
    for month, _ in all_incomes:
        all_months.add(month)
    
    # 按时间顺序处理所有月份
    sorted_months = sorted(all_months)
    for month in sorted_months:
        # 获取当月支出和收入
        expense_amount = float(expense_map.get(month, 0))
        income_amount = float(income_map.get(month, 0))
        
        # 更新累计净额（先加收入，再减支出）
        cumulative_net += income_amount
        cumulative_net -= expense_amount

        # 添加所有月份的数据到显示列表
        complete_expense_data.append({'month': month, 'total': expense_amount})
        complete_income_data.append({'month': month, 'total': income_amount})
        complete_net_data.append({'month': month, 'total': cumulative_net})

        print(f"Debug - Month: {month}")
        print(f"  Income: {income_amount}")
        print(f"  Expense: {expense_amount}")
        print(f"  Cumulative Net: {cumulative_net}")

    print(f"Debug - Monthly data:")
    print(f"Expenses: {complete_expense_data}")
    print(f"Income: {complete_income_data}")
    print(f"Net: {complete_net_data}")

    return render_template('expenses.html',
                           expenses=expenses,
                           pagination=pagination,
                           expense_monthly_data=complete_expense_data,
                           expense_type_data=expense_type_data,
                           income_monthly_data=complete_income_data,
                           net_monthly_data=complete_net_data)


@app.route('/api/expenses', methods=['GET', 'POST'])
@login_required
def get_expenses():
    if request.method == 'POST':
        try:
            # 获取表单数据
            user = request.form.get('user')
            type = request.form.get('type')
            amount = float(request.form.get('amount'))
            purpose = request.form.get('purpose')
            date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()

            # 创建新的支出记录
            expense = Expense(
                user=user,
                type=type,
                amount=amount,
                purpose=purpose,
                date=date
            )

            # 保存到数据库
            db.session.add(expense)
            db.session.commit()

            return jsonify({'success': True, 'message': '支出记录添加成功'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'添加失败：{str(e)}'})

    # GET请求处理
    # 获取当前日期和6个月前的日期
    today = datetime.now()
    six_months_ago = today.replace(day=1)  # 设置为当月1号
    for _ in range(6):
        if six_months_ago.month == 1:
            six_months_ago = six_months_ago.replace(year=six_months_ago.year - 1, month=12)
        else:
            six_months_ago = six_months_ago.replace(month=six_months_ago.month - 1)

    # 获取支出月度数据（最近6个月）
    expense_monthly_data = db.session.query(
        db.func.strftime('%Y-%m', Expense.date).label('month'),
        db.func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= six_months_ago.date(),
        Expense.date <= today.date()
    ).group_by('month').all()

    # 获取支出类型数据（最近6个月）
    expense_type_data = db.session.query(
        Expense.type,
        db.func.sum(Expense.amount).label('total')
    ).filter(
        Expense.date >= six_months_ago.date(),
        Expense.date <= today.date()
    ).group_by(Expense.type).all()

    # 获取收入月度数据（最近6个月）
    income_monthly_data = db.session.query(
        db.func.strftime('%Y-%m', Income.date).label('month'),
        db.func.sum(Income.amount).label('total')
    ).filter(
        Income.date >= six_months_ago.date(),
        Income.date <= today.date()
    ).group_by('month').all()

    # 获取所有历史数据用于计算累计净额
    all_expenses = db.session.query(
        db.func.strftime('%Y-%m', Expense.date).label('month'),
        db.func.sum(Expense.amount).label('total')
    ).group_by('month').order_by('month').all()

    all_incomes = db.session.query(
        db.func.strftime('%Y-%m', Income.date).label('month'),
        db.func.sum(Income.amount).label('total')
    ).group_by('month').order_by('month').all()

    # 创建月份到金额的映射
    expense_map = {month: total for month, total in all_expenses}
    income_map = {month: total for month, total in all_incomes}

    # 计算累计净额（使用所有历史数据）
    cumulative_net = 0
    all_months = set()
    for month, _ in all_expenses:
        all_months.add(month)
    for month, _ in all_incomes:
        all_months.add(month)
    
    # 按时间顺序处理所有月份
    sorted_months = sorted(all_months)
    net_monthly_data = []
    for month in sorted_months:
        # 获取当月支出和收入
        expense_amount = float(expense_map.get(month, 0))
        income_amount = float(income_map.get(month, 0))
        
        # 更新累计净额（先加收入，再减支出）
        cumulative_net += income_amount
        cumulative_net -= expense_amount

        # 添加所有月份的数据到显示列表
        net_monthly_data.append({
            'month': month,
            'total': cumulative_net
        })

    return jsonify({
        'expense_monthly_data': [{'month': m[0], 'total': float(m[1])} for m in expense_monthly_data],
        'expense_type_data': [{'type': t[0], 'total': float(t[1])} for t in expense_type_data],
        'income_monthly_data': [{'month': m[0], 'total': float(m[1])} for m in income_monthly_data],
        'net_monthly_data': net_monthly_data
    })


def create_test_user():
    with app.app_context():
        # 创建第一个管理员账号
        admin1 = Student.query.filter_by(phone='13800138000').first()
        if not admin1:
            admin1 = Student(
                student_no='ADMIN001',
                name='系统管理员',
                phone='13800138000',
                email='admin1@example.com',
                role='管理员',
                status='启用'
            )
            admin1.set_password('123456')
            db.session.add(admin1)

        # 创建第二个管理员账号
        admin2 = Student.query.filter_by(phone='13800138001').first()
        if not admin2:
            admin2 = Student(
                student_no='ADMIN002',
                name='超级管理员',
                phone='13800138001',
                email='admin2@example.com',
                role='管理员',
                status='启用'
            )
            admin2.set_password('123456')
            db.session.add(admin2)

        db.session.commit()


def create_test_expenses():
    with app.app_context():
        if not Expense.query.first():
            # 创建2024年的测试数据
            test_expenses = [
                # 1月数据
                Expense(user='张三', type='教师礼物', amount=500, purpose='教师节礼物', date=datetime(2024, 1, 15)),
                Expense(user='李四', type='活动经费', amount=800, purpose='班级聚会', date=datetime(2024, 1, 20)),
                Expense(user='王五', type='文具用品', amount=200, purpose='购买文具', date=datetime(2024, 1, 25)),

                # 2月数据
                Expense(user='张三', type='教师礼物', amount=600, purpose='教师节礼物', date=datetime(2024, 2, 10)),
                Expense(user='李四', type='活动经费', amount=1000, purpose='班级活动', date=datetime(2024, 2, 15)),
                Expense(user='王五', type='文具用品', amount=300, purpose='购买教材', date=datetime(2024, 2, 20)),

                # 3月数据
                Expense(user='张三', type='教师礼物', amount=400, purpose='教师节礼物', date=datetime(2024, 3, 5)),
                Expense(user='李四', type='活动经费', amount=1200, purpose='班级春游', date=datetime(2024, 3, 10)),
                Expense(user='王五', type='文具用品', amount=250, purpose='购买文具', date=datetime(2024, 3, 15)),

                # 4月数据
                Expense(user='张三', type='教师礼物', amount=550, purpose='教师节礼物', date=datetime(2024, 4, 1)),
                Expense(user='李四', type='活动经费', amount=900, purpose='班级活动', date=datetime(2024, 4, 5)),
                Expense(user='王五', type='文具用品', amount=180, purpose='购买文具', date=datetime(2024, 4, 10)),

                # 5月数据
                Expense(user='张三', type='教师礼物', amount=450, purpose='教师节礼物', date=datetime(2024, 5, 1)),
                Expense(user='李四', type='活动经费', amount=1100, purpose='班级活动', date=datetime(2024, 5, 5)),
                Expense(user='王五', type='文具用品', amount=220, purpose='购买文具', date=datetime(2024, 5, 10)),

                # 6月数据
                Expense(user='张三', type='教师礼物', amount=480, purpose='教师节礼物', date=datetime(2024, 6, 1)),
                Expense(user='李四', type='活动经费', amount=950, purpose='班级活动', date=datetime(2024, 6, 5)),
                Expense(user='王五', type='文具用品', amount=280, purpose='购买文具', date=datetime(2024, 6, 10)),
            ]
            for expense in test_expenses:
                db.session.add(expense)
            db.session.commit()


@app.route('/api/expenses/template')
@login_required
@permission_required(Permissions.EXPENSE_EDIT)
def download_template():
    if not check_permission(Permissions.EXPENSE_VIEW):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        # 创建示例数据
        data = {
            '使用人': ['张三'],
            '使用类型': ['教师礼物'],
            '使用额度': [500.00],
            '用途': ['教师节礼物'],
            '使用日期': ['2024-01-15']
        }
        df = pd.DataFrame(data)

        # 创建临时文件
        filename = 'expense_template.xlsx'
        filepath = os.path.join(app.instance_path, filename)

        # 确保instance目录存在
        os.makedirs(app.instance_path, exist_ok=True)

        # 保存为Excel文件
        df.to_excel(filepath, index=False)

        # 发送文件
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        return jsonify({'success': False, 'message': f'生成模板失败：{str(e)}'})


@app.route('/api/expenses/<int:id>', methods=['DELETE'])
@login_required
@permission_required(Permissions.EXPENSE_EDIT)
def delete_expense(id):
    if not check_permission(Permissions.EXPENSE_VIEW):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        expense = Expense.query.get_or_404(id)
        db.session.delete(expense)
        db.session.commit()
        return jsonify({'success': True, 'message': '支出记录删除成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'删除失败：{str(e)}'})


@app.route('/api/expenses/<int:id>', methods=['PUT'])
@login_required
@permission_required(Permissions.EXPENSE_EDIT)
def update_expense(id):
    if not check_permission(Permissions.EXPENSE_VIEW):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        expense = Expense.query.get_or_404(id)

        # 更新数据
        expense.user = request.form.get('user')
        expense.type = request.form.get('type')
        expense.amount = float(request.form.get('amount'))
        expense.purpose = request.form.get('purpose')
        expense.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()

        db.session.commit()
        return jsonify({'success': True, 'message': '支出记录更新成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'更新失败：{str(e)}'})


@app.route('/api/expenses/import', methods=['POST'])
@login_required
@permission_required(Permissions.EXPENSE_EDIT)
def import_expenses():
    if not check_permission(Permissions.EXPENSE_VIEW):
        flash('您没有该权限')
        return redirect(url_for('index'))
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': '没有上传文件'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': '没有选择文件'})

        if not file.filename.endswith(('.xlsx', '.xls')):
            return jsonify({'success': False, 'message': '不支持的文件格式'})

        # 读取Excel文件
        df = pd.read_excel(file)

        # 验证数据
        required_columns = ['使用人', '使用类型', '使用额度', '用途', '使用日期']
        if not all(col in df.columns for col in required_columns):
            return jsonify({'success': False, 'message': '文件格式不正确，请使用模板文件'})

        # 导入数据
        for _, row in df.iterrows():
            expense = Expense(
                user=row['使用人'],
                type=row['使用类型'],
                amount=float(row['使用额度']),
                purpose=row['用途'],
                date=pd.to_datetime(row['使用日期']).date()
            )
            db.session.add(expense)

        db.session.commit()
        return jsonify({'success': True, 'message': '导入成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'导入失败：{str(e)}'})


# 修改密码
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('新密码和确认密码不一致')
            return redirect(url_for('change_password'))

        student = Student.query.get(current_user.id)
        if student and student.check_password(old_password):
            student.set_password(new_password)
            db.session.commit()
            flash('密码修改成功')
            return redirect(url_for('expenses'))
        else:
            flash('原密码错误')
    return render_template('change_password.html')

# 重置密码
@app.route('/reset_password/<int:student_id>')
@login_required
@permission_required(Permissions.STUDENT_EDIT)
def reset_password(student_id):
    if not check_permission(Permissions.STUDENT_EDIT):
        flash('您没有该权限')
        return redirect(url_for('index'))
    
    student = Student.query.get_or_404(student_id)
    student.set_password('123456')
    db.session.commit()
    flash('密码已重置为123456')
    return redirect(url_for('students'))

# 初始化数据库和测试数据
def init_db():
    with app.app_context():
        # 创建所有数据库表
        db.create_all()  # 只创建表，不删除现有数据

        # 创建管理员账号
        create_test_user()  # 创建管理员测试账号
        create_test_roles()  # 创建角色数据

def create_test_data():
    """创建测试数据，包括最近6个月的支出和收入记录"""
    today = datetime.now()
    
    # 创建最近6个月的测试数据
    for i in range(6):
        # 计算日期
        if today.month - i <= 0:
            year = today.year - 1
            month = today.month - i + 12
        else:
            year = today.year
            month = today.month - i
            
        # 创建支出记录
        expense = Expense(
            expense_no=f"{year}{month:02d}001",
            user="测试用户",
            type="活动经费",
            amount=1000.0 * (i + 1),
            purpose=f"{year}年{month}月测试支出",
            date=datetime(year, month, 1).date()
        )
        db.session.add(expense)
        
        # 创建收入记录
        income = Income(
            income_no=f"{year}{month:02d}001",
            user="测试用户",
            amount=2000.0 * (i + 1),
            date=datetime(year, month, 1).date()
        )
        db.session.add(income)
    
    db.session.commit()

# 在应用启动时创建测试数据
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # 检查是否需要创建测试数据
        if not Expense.query.first():
            create_test_data()
        app.run(host='0.0.0.0', port=8090, debug=True)

