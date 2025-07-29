from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_caching import Cache
import requests
from datetime import datetime, timedelta
import json
from dotenv import load_dotenv
import os
from urllib.parse import urlencode

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5 minutes cache

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
cache = Cache(app)

# GitHub OAuth Config
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_AUTH_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_API_URL = 'https://api.github.com'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    github_id = db.Column(db.Integer, unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    access_token = db.Column(db.String(200))
    last_updated = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

def get_github_user(access_token):
    headers = {'Authorization': f'token {access_token}'}
    response = requests.get(f'{GITHUB_API_URL}/user', headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def get_github_repos(access_token, username):
    headers = {'Authorization': f'token {access_token}'}
    repos = []
    page = 1
    while True:
        response = requests.get(
            f'{GITHUB_API_URL}/users/{username}/repos',
            headers=headers,
            params={'page': page, 'per_page': 100}
        )
        if response.status_code != 200:
            break
        new_repos = response.json()
        if not new_repos:
            break
        repos.extend(new_repos)
        page += 1
    return repos

def get_repo_stats(access_token, owner, repo):
    headers = {'Authorization': f'token {access_token}'}
    
    # Check rate limits first
    rate_limit = requests.get(f'{GITHUB_API_URL}/rate_limit', headers=headers).json()
    if rate_limit['resources']['core']['remaining'] < 10:
        return {'error': 'Approaching GitHub API rate limit'}
    
    # Get commits (last year)
    commits_url = f'{GITHUB_API_URL}/repos/{owner}/{repo}/stats/commit_activity'
    commits_response = requests.get(commits_url, headers=headers)
    commits = commits_response.json() if commits_response.status_code == 200 else []
    
    # Get languages
    languages_url = f'{GITHUB_API_URL}/repos/{owner}/{repo}/languages'
    languages_response = requests.get(languages_url, headers=headers)
    languages = languages_response.json() if languages_response.status_code == 200 else {}
    
    return {
        'commits': commits,
        'languages': languages,
        'stars': requests.get(
            f'{GITHUB_API_URL}/repos/{owner}/{repo}',
            headers=headers
        ).json().get('stargazers_count', 0)
    }

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    params = {
        'client_id': GITHUB_CLIENT_ID,
        'scope': 'repo,user',
        'redirect_uri': url_for('authorize', _external=True)
    }
    auth_url = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/authorize')
def authorize():
    code = request.args.get('code')
    if not code:
        flash('Authorization failed: no code returned from GitHub', 'danger')
        return redirect(url_for('index'))
    
    # Exchange code for access token
    data = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': code,
        'redirect_uri': url_for('authorize', _external=True)
    }
    headers = {'Accept': 'application/json'}
    response = requests.post(GITHUB_TOKEN_URL, data=data, headers=headers)
    
    if response.status_code != 200:
        flash('Failed to obtain access token from GitHub', 'danger')
        return redirect(url_for('index'))
    
    access_token = response.json().get('access_token')
    if not access_token:
        flash('No access token returned from GitHub', 'danger')
        return redirect(url_for('index'))
    
    # Get user info
    user_data = get_github_user(access_token)
    if not user_data:
        flash('Failed to fetch user data from GitHub', 'danger')
        return redirect(url_for('index'))
    
    # Create or update user
    user = User.query.filter_by(github_id=user_data['id']).first()
    if not user:
        user = User(
            github_id=user_data['id'],
            username=user_data['login'],
            access_token=access_token,
            last_updated=datetime.utcnow()
        )
        db.session.add(user)
    else:
        user.access_token = access_token
        user.last_updated = datetime.utcnow()
    
    db.session.commit()
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@cache.cached(timeout=300, key_prefix=lambda: f"user_{current_user.id}")
def dashboard():
    # Check if data is stale (older than 1 hour)
    if datetime.utcnow() - current_user.last_updated > timedelta(hours=1):
        cache.delete(f"user_{current_user.id}")
        current_user.last_updated = datetime.utcnow()
        db.session.commit()
    
    try:
        repos = get_github_repos(current_user.access_token, current_user.username)
        if isinstance(repos, dict) and repos.get('message'):
            if 'API rate limit exceeded' in repos['message']:
                flash('GitHub API rate limit exceeded. Please try again later.', 'warning')
                return render_template('dashboard.html', repos=[], rate_limit=True)
        
        repo_stats = []
        for repo in repos[:20]:  # Limit to first 20 repos for demo
            stats = get_repo_stats(current_user.access_token, repo['owner']['login'], repo['name'])
            repo_stats.append({
                'name': repo['name'],
                'description': repo['description'],
                'html_url': repo['html_url'],
                'stars': repo['stargazers_count'],
                'forks': repo['forks_count'],
                'stats': stats
            })
        
        return render_template('dashboard.html', repos=repo_stats, username=current_user.username)
    except Exception as e:
        flash(f'Error fetching GitHub data: {str(e)}', 'danger')
        return render_template('dashboard.html', repos=[], error=True)

@app.route('/repo/<owner>/<repo>')
@login_required
@cache.cached(timeout=300, query_string=True)
def repo_detail(owner, repo):
    try:
        stats = get_repo_stats(current_user.access_token, owner, repo)
        if stats.get('error'):
            flash(stats['error'], 'warning')
            return redirect(url_for('dashboard'))
        
        # Process commits data
        commits_data = []
        if stats.get('commits'):
            for week in stats['commits']:
                if week:  # Skip empty weeks
                    week_start = datetime.fromtimestamp(week['week']).strftime('%Y-%m-%d')
                    commits_data.append({
                        'week': week_start,
                        'commits': week['total']
                    })
        
        # Process languages data
        languages_data = []
        total_bytes = sum(stats['languages'].values())
        if total_bytes > 0:
            for lang, bytes_count in stats['languages'].items():
                languages_data.append({
                    'language': lang,
                    'percentage': (bytes_count / total_bytes) * 100
                })
        
        return render_template(
            'repo_detail.html',
            owner=owner,
            repo=repo,
            stars=stats.get('stars', 0),
            commits_data=commits_data,
            languages_data=languages_data
        )
    except Exception as e:
        flash(f'Error fetching repository data: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
