from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
from sqlalchemy import text, Column
from sqlalchemy.types import JSON

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project_dashboard.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models will be defined here

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    projects = db.relationship('Project', backref='user', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    client_name = db.Column(db.String(100), nullable=True)
    objectives = db.Column(db.Text, nullable=True)
    scope = db.Column(db.Text, nullable=True)
    budget = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    planned_start_date = db.Column(db.Date, nullable=True)
    planned_complete_date = db.Column(db.Date, nullable=True)
    checklist_items = db.relationship('ChecklistItem', backref='project', lazy=True)
    actuals = db.Column(db.Float, nullable=True)

    @property
    def formatted_budget(self):
        return f"${self.budget:,.2f}" if self.budget is not None else "Not set"

    @property
    def formatted_actuals(self):
        return f"${self.actuals:,.2f}" if self.actuals is not None else "Not set"

class ChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)

class RiskIssue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    type = db.Column(db.String(10), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.Date, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    impact = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    mitigation = db.Column(db.Text)
    notes = db.Column(db.Text)

    project = db.relationship('Project', backref=db.backref('risk_issues', lazy=True))

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    project = db.relationship('Project', backref=db.backref('resources', lazy=True))

class ResourceType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False, unique=True)
    rate = db.Column(db.Float, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# This line ensures the tables exist, but won't modify existing tables
with app.app_context():
    db.create_all()

# Routes will be defined here

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects)

@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        # Handle the budget field
        budget_str = request.form['budget']
        budget = float(budget_str) if budget_str else None

        # Handle date fields
        planned_start_date = None
        if request.form['planned_start_date']:
            planned_start_date = datetime.strptime(request.form['planned_start_date'], '%Y-%m-%d').date()

        planned_complete_date = None
        if request.form['planned_complete_date']:
            planned_complete_date = datetime.strptime(request.form['planned_complete_date'], '%Y-%m-%d').date()

        new_project = Project(
            name=request.form['name'],
            client_name=request.form['client_name'],
            objectives=request.form['objectives'],
            scope=request.form['scope'],
            budget=budget,
            user_id=current_user.id,
            planned_start_date=planned_start_date,
            planned_complete_date=planned_complete_date
        )
        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('create_project.html')

@app.route('/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    if request.method == 'POST':
        if 'add_checklist_item' in request.form:
            new_item = ChecklistItem(
                project_id=project.id,
                description=request.form['checklist_item']
            )
            db.session.add(new_item)
            db.session.commit()
        elif 'toggle_checklist_item' in request.form:
            item_id = int(request.form['toggle_checklist_item'])
            item = ChecklistItem.query.get(item_id)
            if item and item.project_id == project.id:
                item.completed = not item.completed
                db.session.commit()
    return render_template('view_project.html', project=project)

# Add this new route to delete checklist items
@app.route('/delete_checklist_item/<int:item_id>', methods=['POST'])
@login_required
def delete_checklist_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    if item.project.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('view_project', project_id=item.project_id))

# Add this new route to handle checkbox toggling without page reload
@app.route('/toggle_checklist_item/<int:item_id>', methods=['POST'])
@login_required
def toggle_checklist_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    if item.project.user_id == current_user.id:
        item.completed = not item.completed
        db.session.commit()
        
        project = item.project
        completed_count = sum(1 for item in project.checklist_items if item.completed)
        total_count = len(project.checklist_items)
        progress_percentage = (completed_count / total_count * 100) if total_count > 0 else 0
        
        return jsonify({
            'success': True,
            'completed_count': completed_count,
            'total_count': total_count,
            'progress_percentage': round(progress_percentage)
        })
    return jsonify({'success': False}), 403

@app.route('/update_project/<int:project_id>/<string:section>', methods=['POST'])
@login_required
def update_project(project_id, section):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    data = request.json
    
    if section not in ['objectives', 'timeline', 'budget', 'scope']:
        return jsonify({'success': False, 'message': 'Invalid section'}), 400
    
    if section == 'objectives':
        project.objectives = data.get('objectives')
    elif section == 'timeline':
        project.planned_start_date = datetime.strptime(data.get('planned_start_date'), '%Y-%m-%d').date() if data.get('planned_start_date') else None
        project.planned_complete_date = datetime.strptime(data.get('planned_complete_date'), '%Y-%m-%d').date() if data.get('planned_complete_date') else None
    elif section == 'budget':
        project.budget = float(data.get('budget')) if data.get('budget') else None
        project.actuals = float(data.get('actuals')) if data.get('actuals') else None
    elif section == 'scope':
        project.scope = data.get('scope')
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Project updated successfully',
        'objectives': project.objectives,
        'planned_start_date': project.planned_start_date.isoformat() if project.planned_start_date else None,
        'planned_complete_date': project.planned_complete_date.isoformat() if project.planned_complete_date else None,
        'budget': project.budget,
        'actuals': project.actuals,
        'scope': project.scope
    })

@app.route('/add_risk_issue/<int:project_id>', methods=['POST'])
@login_required
def add_risk_issue(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.json
    new_risk_issue = RiskIssue(
        project_id=project_id,
        type=data['type'],
        title=data['title'],
        date_created=datetime.strptime(data['dateCreated'], '%Y-%m-%d').date(),
        severity=data['severity'],
        impact=','.join(data['impact']),
        status=data['status'],
        mitigation=data.get('mitigation', ''),
        notes=data.get('notes', '')
    )

    db.session.add(new_risk_issue)
    db.session.commit()

    return jsonify({'success': True, 'risk_issue': {
        'id': new_risk_issue.id,
        'type': new_risk_issue.type,
        'title': new_risk_issue.title,
        'dateCreated': new_risk_issue.date_created.isoformat(),
        'severity': new_risk_issue.severity,
        'impact': new_risk_issue.impact.split(','),
        'status': new_risk_issue.status,
        'mitigation': new_risk_issue.mitigation,
        'notes': new_risk_issue.notes
    }})

@app.route('/get_risk_issues/<int:project_id>', methods=['GET'])
@login_required
def get_risk_issues(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    risk_issues = RiskIssue.query.filter_by(project_id=project_id).all()
    return jsonify({'success': True, 'risk_issues': [{
        'id': ri.id,
        'type': ri.type,
        'title': ri.title,
        'dateCreated': ri.date_created.strftime('%Y-%m-%d'),  # Format the date
        'severity': ri.severity,
        'impact': ri.impact.split(','),
        'status': ri.status,
        'mitigation': ri.mitigation,
        'notes': ri.notes
    } for ri in risk_issues]})

@app.route('/update_risk_issue/<int:risk_issue_id>', methods=['POST'])
@login_required
def update_risk_issue(risk_issue_id):
    risk_issue = RiskIssue.query.get_or_404(risk_issue_id)
    if risk_issue.project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.json
    risk_issue.type = data['type']
    risk_issue.title = data['title']
    risk_issue.severity = data['severity']
    risk_issue.impact = ','.join(data['impact'])
    risk_issue.status = data['status']
    risk_issue.mitigation = data.get('mitigation', '')
    risk_issue.notes = data.get('notes', '')

    db.session.commit()

    return jsonify({'success': True, 'risk_issue': {
        'id': risk_issue.id,
        'type': risk_issue.type,
        'title': risk_issue.title,
        'dateCreated': risk_issue.date_created.isoformat(),
        'severity': risk_issue.severity,
        'impact': risk_issue.impact.split(','),
        'status': risk_issue.status,
        'mitigation': risk_issue.mitigation,
        'notes': risk_issue.notes
    }})

@app.route('/delete_risk_issue/<int:risk_issue_id>', methods=['POST'])
@login_required
def delete_risk_issue(risk_issue_id):
    risk_issue = RiskIssue.query.get_or_404(risk_issue_id)
    if risk_issue.project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    db.session.delete(risk_issue)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/toggle_contract/<int:project_id>/<string:contract_type>', methods=['POST'])
def toggle_contract(project_id, contract_type):
    try:
        data = request.json
        project = Project.query.get_or_404(project_id)
        
        if contract_type == 'sow':
            project.sow_completed = data['completed']
        elif contract_type == 'po':
            project.po_completed = data['completed']
        else:
            return jsonify({'success': False, 'error': 'Invalid contract type'}), 400
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error in toggle_contract: {str(e)}")  # Log the error
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/add_resource/<int:project_id>', methods=['POST'])
@login_required
def add_resource(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    data = request.json
    new_resource = Resource(
        project_id=project_id,
        name=data['name'],
        resource_type=data['resourceType']
    )

    db.session.add(new_resource)
    db.session.commit()

    return jsonify({
        'success': True,
        'resource': {
            'id': new_resource.id,
            'name': new_resource.name,
            'resourceType': new_resource.resource_type
        }
    })

@app.route('/get_resources/<int:project_id>', methods=['GET'])
@login_required
def get_resources(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    resources = Resource.query.filter_by(project_id=project_id).all()
    return jsonify({
        'success': True,
        'resources': [{
            'id': r.id,
            'name': r.name,
            'resourceType': r.resource_type
        } for r in resources]
    })

@app.route('/delete_resource/<int:resource_id>', methods=['POST'])
@login_required
def delete_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    if resource.project.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    db.session.delete(resource)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/get_resource_types', methods=['GET'])
@login_required
def get_resource_types():
    resource_types = ResourceType.query.all()
    return jsonify({
        'success': True,
        'resource_types': [{
            'id': rt.id,
            'type': rt.type,
            'rate': rt.rate
        } for rt in resource_types]
    })

@app.route('/add_resource_type', methods=['POST'])
@login_required
def add_resource_type():
    data = request.json
    new_resource_type = ResourceType(type=data['type'], rate=data['rate'])
    db.session.add(new_resource_type)
    db.session.commit()
    return jsonify({
        'success': True,
        'resource_type': {
            'id': new_resource_type.id,
            'type': new_resource_type.type,
            'rate': new_resource_type.rate
        }
    })

@app.route('/update_resource_type/<int:type_id>', methods=['POST'])
@login_required
def update_resource_type(type_id):
    resource_type = ResourceType.query.get_or_404(type_id)
    data = request.json
    resource_type.type = data['type']
    resource_type.rate = data['rate']
    db.session.commit()
    return jsonify({
        'success': True,
        'resource_type': {
            'id': resource_type.id,
            'type': resource_type.type,
            'rate': resource_type.rate
        }
    })

@app.route('/delete_resource_type/<int:type_id>', methods=['POST'])
@login_required
def delete_resource_type(type_id):
    resource_type = ResourceType.query.get_or_404(type_id)
    db.session.delete(resource_type)
    db.session.commit()
    return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context():
        # Remove the following line:
        # db.drop_all()
        db.create_all()
    app.run(debug=True)