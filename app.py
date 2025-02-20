from flask import Flask, send_file, render_template, redirect, abort, url_for, request, session, render_template_string, Response, make_response
import os, sys, secrets, bcrypt, json, pathlib, shutil, string
from typing import Dict, Any, Callable, Tuple, Union, Optional, List, TypedDict
from functools import wraps

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

class SharedLink(TypedDict):
    username:str
    link:str
    file:str

class UserData(TypedDict):
    password:str
    max_size:int
    tokens:List[str]

file_dir : str = os.path.dirname(os.path.realpath(__file__))
frozen_dir = os.path.dirname(sys.executable)
executable_dir : str = os.path.dirname(os.path.realpath(__file__))
if getattr(sys, 'frozen', False):
    executable_dir = os.path.dirname(sys.executable)
directory_config : str = os.path.join(executable_dir, 'path.txt')
admin_config : str = os.path.join(executable_dir, 'admin.txt')
files_directory : str = os.path.join(executable_dir, 'data')
admin_password : str = '2024'
allowed_characters : str = string.ascii_letters + string.digits + '_-.() '

if os.path.isfile(directory_config):
    with open(directory_config, 'r') as file:
        files_directory = file.read().strip()

if os.path.isfile(admin_config):
    with open(admin_config, 'r') as file:
        admin_password = file.read().strip()

app : Flask = Flask(__name__)
app.secret_key = 'c2d94b0427e81f7889ccadd89d46da4d'

def hash_password(password:str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

account_data : Dict[str, UserData] = {
    'admin' : {
        'password' : hash_password(admin_password),
        'max_size' : 0,
        'tokens' : []
    }
}

def load_account_data() -> None:
    global account_data
    with open(os.path.join(files_directory, 'accounts.json'), 'r') as file:
        account_data = json.load(file)
    for account in account_data.keys():
        os.makedirs(os.path.join(files_directory, account), exist_ok=True)

links_data : Dict[str, SharedLink] = {}

def load_links_data() -> None:
    global links_data
    with open(os.path.join(files_directory, 'links.json'), 'r') as file:
        links_data = json.load(file)


def save_account_data() -> None:
    for account in account_data.keys():
        os.makedirs(os.path.join(files_directory, account), exist_ok=True)
    with open(os.path.join(files_directory, 'accounts.json'), 'w') as  file:
        json.dump(account_data, file, indent=4)

def save_links_data() -> None:
    with open(os.path.join(files_directory, 'links.json'), 'w') as  file:
        json.dump(links_data, file, indent=4)

def verify_password(password:str, hashed_password:str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_directory_size_integer(dir:str) -> int:
    return sum(f.stat().st_size for f in pathlib.Path(dir).glob('**/*') if f.is_file())

def get_human_size(num:int) -> str:
    suffix : str = 'B'
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def is_clean(path:str) -> bool:
    invalid_chars : str = r'\:*?<>|%'
    if '..' in path or any(char in invalid_chars for char in path) or path.isspace():
        return False
    return True

def login_required(view_func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view_func)
    def wrapped_view(*args: Tuple[Any, ...], **kwargs: Dict[str, Any]) -> Union[str, Any]:
        if 'username' in session:
            if session['username'] in account_data.keys():
                if 'token' in session:
                    if session['token'] in account_data[session['username']]['tokens']:
                        return view_func(*args, **kwargs)
            return redirect(url_for('logout'))
        else:
            return redirect(url_for('login'))
    return wrapped_view

@app.route('/')
def home() -> Union[str, Any]:
    if 'username' in session:
        return redirect(url_for('view'))
    return render_template('home.html')

@app.route('/user/')
@login_required
def user_page() -> Union[str, Any]:
    current_size : str = get_human_size(get_directory_size_integer(os.path.join(files_directory, session['username'])))
    max_size : str = 'NAN'
    shared_links : List[str] = [link['link'] for link in links_data.values() if link['username'] == session['username']]
    if account_data[session['username']]['max_size'] > 0:
        max_size = get_human_size(account_data[session['username']]['max_size'])
    return render_template('user.html', current_size=current_size, max_size=max_size, shared_links=shared_links)

def sort_key(dir:str,item:str) -> Tuple[bool, str]:
    path : str = os.path.join(dir, item)
    return (not os.path.isdir(path), item)

@app.route('/view/')
@app.route('/view/<path:dir>/')
@login_required
def view(dir:str='') -> Union[str, Any]:
    if not is_clean(dir):
        abort(404)
    if not os.path.exists(os.path.join(files_directory, session['username'], dir)):
        abort(404)
    up_dir : str = os.path.dirname(dir)
    size : str = get_human_size(get_directory_size_integer(os.path.join(files_directory, session['username'], dir)))
    file_list : Dict[str, bool] = {k:os.path.isdir(os.path.join(files_directory, session['username'], dir, k)) for k in sorted(os.listdir(os.path.join(files_directory, session['username'], dir)), key=lambda x: sort_key(os.path.join(files_directory, session['username'], dir), x))}
    return render_template('view.html', file_list=file_list, join=os.path.join, current_dir=dir, up_dir=up_dir, folder_size=size)

@app.route('/info/<path:file>')
@login_required
def info(file:str) -> Union[str, Any]:
    if not is_clean(file):
        abort(404)
    file_internal : str = os.path.join(files_directory, session['username'], file)
    if not os.path.exists(file_internal):
        abort(404)
    is_dir : bool = os.path.isdir(file_internal)
    size : str = get_human_size(pathlib.Path(file_internal).stat().st_size)
    if is_dir:
        size = get_human_size(get_directory_size_integer(file_internal))
    return render_template('info.html', file_name=os.path.basename(file), file_size=size, file_path=file, current_dir=os.path.dirname(file), is_dir=is_dir)

@app.route('/new_folder/', methods=['GET', 'POST'])
@app.route('/new_folder/<path:dir>/', methods=['GET', 'POST'])
@login_required
def new_folder(dir:str='') -> Union[str, Any]:
    if not is_clean(dir):
        abort(404)
    if not os.path.isdir(os.path.join(files_directory, session['username'], dir)):
        abort(404)
    if request.method == 'POST':
        new_folder_name : Optional[str] = request.form.get('folder_name')
        if not new_folder_name:
            return render_template('new_folder.html', current_dir=dir, message_error='Folder name is empty')
        if len(new_folder_name) > 250:
            return render_template('new_folder.html', current_dir=dir, message_error='Folder name is too long')
        for char in new_folder_name:
            if not char in allowed_characters:
                return render_template('new_folder.html', current_dir=dir, message_error='Folder name is invalid')
        if not is_clean(new_folder_name):
            return render_template('new_folder.html', current_dir=dir, message_error='Folder name is invalid')
        if os.path.exists(os.path.join(files_directory, session['username'], dir, new_folder_name)):
            return render_template('new_folder.html', current_dir=dir, message_error='Folder already exists')
        os.mkdir(os.path.join(files_directory, session['username'], dir, new_folder_name))
        return redirect(url_for('view', dir=dir))
    return render_template('new_folder.html', current_dir=dir)

@app.route('/move/', methods=['GET', 'POST'])
@app.route('/move/<path:file>', methods=['GET', 'POST'])
@login_required
def move(file:str='') -> Union[str, Any]:
    if not is_clean(file):
        abort(404)
    if request.method == 'POST':
        clipboard : Optional[str] = session.get('clipboard', None)
        if clipboard:
            file_internal : str = os.path.join(files_directory, session['username'], clipboard)
            path_internal : str = os.path.join(files_directory, session['username'], file)
            if not os.path.exists(file_internal):
                abort(404)
            if not os.path.isdir(path_internal):
                abort(404)
            if os.path.dirname(file_internal) == path_internal:
                abort(404)
            shutil.move(file_internal, path_internal)
            session.pop('clipboard', None)
            return redirect(url_for('view', dir=os.path.dirname(file)))
    file_internal : str = os.path.join(files_directory, session['username'], file)
    if not os.path.exists(file_internal):
        abort(404)
    session['clipboard'] = file
    return redirect(url_for('view', dir=os.path.dirname(file)))

@app.route('/rename/<path:file>', methods=['GET', 'POST'])
@login_required
def rename_page(file:str) -> Union[str, Any]:
    if not is_clean(file):
        abort(404)
    file_internal : str = os.path.join(files_directory, session['username'], file)
    if not os.path.exists(file_internal):
        abort(404)
    dirname : str = os.path.dirname(file)
    if request.method == 'POST':
        new_file_name : Optional[str] = request.form.get('file_name')
        if not new_file_name:
            return render_template('rename.html', file_name=os.path.basename(file), file_path=file, current_dir=dirname, message_error='File name is empty')
        if len(new_file_name) > 250:
            return render_template('rename.html', file_name=os.path.basename(file), file_path=file, current_dir=dirname, message_error='File name is too long')
        if not is_clean(new_file_name):
            return render_template('rename.html', file_name=os.path.basename(file), file_path=file, current_dir=dirname, message_error='File name is invalid')
        for char in new_file_name:
            if not char in allowed_characters:
                return render_template('info.html', file_name=os.path.basename(file), file_path=file, current_dir=dirname, message_error='File name is invalid')
        os.rename(file_internal, os.path.join(os.path.dirname(file_internal), new_file_name))
        return redirect(url_for('view', dir=dirname))
    return render_template('rename.html', file_name=os.path.basename(file), file_path=file, current_dir=dirname)

@app.route('/delete/<path:file>')
@login_required
def delete(file:str) -> Union[str, Any]:
    if not is_clean(file):
        abort(404)
    file_internal : str = os.path.join(files_directory, session['username'], file)
    if not os.path.exists(file_internal):
        abort(404)
    if os.path.isdir(file_internal):
        shutil.rmtree(file_internal, True)
    else:
        os.remove(file_internal)
    return redirect(url_for('view', dir=os.path.dirname(file)))

@app.route('/link/<path:file>')
@login_required
def get_link(file:str) -> Union[str, Any]:
    if not is_clean(file):
        abort(404)
    file_internal : str = os.path.join(files_directory, session['username'], file)
    if not os.path.isfile(file_internal):
        abort(404)
    if file_internal in [link['file'] for link in links_data.values()]:
        link : str = next((link['link'] for link in links_data.values() if link['file'] == file_internal))
        return redirect(url_for('public_view', code=link))
    code : str = secrets.token_hex(8)
    while code in links_data.keys():
        code = secrets.token_hex(8)
    links_data[code] = {
        'username' : session['username'],
        'file' : file_internal,
        'link' : code
    }
    save_links_data()
    return render_template('get_link.html', file_name=os.path.basename(file), current_dir=os.path.dirname(file), link_code=code)

@app.route('/revoke/<code>/')
@login_required
def revoke_link(code:str) -> Union[str, Any]:
    if not code in links_data.keys():
        abort(404)
    if links_data[code]['username'] != session['username']:
        abort(404)
    links_data.pop(code, None)
    save_links_data()
    return redirect(url_for('view'))

@app.route('/public/<code>/')
def public_view(code:str) -> Union[str, Any]:
    if not code in links_data.keys():
        abort(404)
    file : str = links_data[code]['file']
    if not os.path.isfile(file):
        links_data.pop(code, None)
        save_links_data()
        abort(404)
    size : str = get_human_size(pathlib.Path(file).stat().st_size)
    return render_template('public.html', file_name=os.path.basename(file), file_size=size, user=links_data[code]['username'], link_code=code)

@app.route('/public/<code>/download/')
def public_download(code:str) -> Union[str, Any]:
    if not code in links_data.keys():
        abort(404)
    file : str = links_data[code]['file']
    if not os.path.isfile(file):
        links_data.pop(code, None)
        save_links_data()
        abort(404)
    return send_file(file, as_attachment=True)

@app.route('/download/<path:file>')
@login_required
def download(file:str) -> Union[str, Any]:
    if not is_clean(file):
        abort(404)
    file : str = os.path.join(files_directory, session['username'], file)
    if not os.path.isfile(file):
        abort(404)
    return send_file(file, as_attachment=True)

@app.route('/upload/', methods=['GET', 'POST'])
@app.route('/upload/<path:dir>', methods=['GET', 'POST'])
@login_required
def upload(dir:str='') -> Union[str, Any]:
    if not is_clean(dir):
        abort(404)
    if not os.path.exists(os.path.join(files_directory, session['username'], dir)):
        abort(404)
    if request.method == 'POST':
        max_size : int = account_data[session['username']]['max_size']
        current_size : int = get_directory_size_integer(os.path.join(files_directory, session['username']))
        missing_size : int = 0
        upload_size : int = 0
        for uploaded_file in request.files.getlist('uploads'):
            upload_size += uploaded_file.seek(0, os.SEEK_END)
            uploaded_file.seek(0, os.SEEK_SET)
        if max_size:
            if current_size + upload_size > max_size:
                missing_size = abs(current_size + upload_size - max_size)
        if missing_size:
            return render_template_string('Account size exceeded by %s' % get_human_size(missing_size))
        invalid_file_list : List[str] = []
        for uploaded_file in request.files.getlist('uploads'):
            if not is_clean(uploaded_file.filename):
                invalid_file_list.append(uploaded_file.filename)
                continue
            for char in uploaded_file.filename:
                if not char in allowed_characters:
                    invalid_file_list.append(uploaded_file.filename)
                    break
        if invalid_file_list:
            error : str = '<br>'.join(['The following files are invalid:'] + invalid_file_list)
            return render_template_string(error)
        for uploaded_file in request.files.getlist('uploads'):
            uploaded_file.save(os.path.join(files_directory, session['username'], dir, secure_filename(uploaded_file.filename)))
        redirect_response : Response = make_response('Redirect')
        redirect_response.headers['HX-Redirect'] = url_for('view', dir=dir)
        return redirect_response
    return render_template('upload.html', upload_dir=dir)

@app.route('/login/', methods=['GET', 'POST'])
def login() -> Union[str, Any]:
    if request.method == 'POST':
        username : Optional[str] = request.form.get('login_name')
        password : Optional[str] = request.form.get('login_password')
        if not username:
            return render_template('login.html', message_error='Username is empty')
        username = username.lower()
        if not password:
            return render_template('login.html', message_error='Password is empty')
        if not username in account_data.keys():
            return render_template('login.html', message_error='Error')
        if not verify_password(password, account_data[username]['password']):
            return render_template('login.html', message_error='User password does not match')
        token : str = secrets.token_hex(16)
        account_data[username]['tokens'].append(token)
        session['token'] = token
        session['username'] = username
        save_account_data()
        return redirect(url_for('view'))
    return render_template('login.html')

@app.route('/logout/')
def logout() -> Any:
    token : Optional[str] = session.pop('token', None)
    if token and 'username' in session:
        if session['username'] in account_data.keys():
            if token in account_data[session['username']]['tokens']:
                account_data[session['username']]['tokens'].remove(token)
                save_account_data()
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/logout_global/')
def logout_global() -> Any:
    token : Optional[str] = session.pop('token', None)
    account_data[session['username']]['tokens'] = []
    save_account_data()
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/clear/')
def clear() -> Any:
    session.pop('clipboard', None)
    return redirect(request.referrer)

@app.errorhandler(404)
def denied(error:Exception) -> Union[str, Any]:
    return render_template('404.html'), 404

@app.route('/reload_accounts/')
@login_required
def reload_accounts() -> Union[str, Any]:
    if session['username'] != 'admin':
        abort(404)
    load_account_data()
    return redirect(request.referrer)

@app.route('/reload_links/')
@login_required
def reload_links() -> Union[str, Any]:
    if session['username'] != 'admin':
        abort(404)
    load_links_data()
    return redirect(request.referrer)

@app.route('/new_account/', methods=['GET', 'POST'])
@login_required
def new_account() -> Union[str, Any]:
    if session['username'] != 'admin':
        abort(404)
    if request.method == 'POST':
        username : str = request.form.get('login_name', '')
        password : str = request.form.get('login_password', '')
        input_size : str = request.form.get('account_size', '')
        input_size_option : str = request.form.get('size_option', '')
        if not username:
            return render_template('new_account.html', message_error='Username is empty')
        username = username.lower()
        if not input_size_option:
            return render_template('new_account.html', message_error='Account size option is empty')
        if not input_size_option.isdigit():
            return render_template('new_account.html', message_error='Account size option must be a number')
        if not input_size:
            return render_template('new_account.html', message_error='Account size is empty')
        if not input_size.isdigit():
            return render_template('new_account.html', message_error='Account size must be a number')
        size : int = int(input_size)
        size_option : int = int(input_size_option)
        if size < 0:
            return render_template('new_account.html', message_error='Account size must be equal or larger than 0')
        for character in username:
            if not character in string.ascii_lowercase:
                return render_template('new_account.html', message_error='Username must be lowercase ascii')
        if not password:
            return render_template('new_account.html', message_error='Password is empty')
        if username in account_data.keys():
            return render_template('new_account.html', message_error='Username taken') 
        account_data[username] = {
            'password' : hash_password(password),
            'max_size' : size * size_option,
            'tokens' : []
        }
        save_account_data()
        return redirect(url_for('user_page'))
    return render_template('new_account.html')

@app.route('/remove_account/', methods=['GET', 'POST'])
@login_required
def remove_account() -> Union[str, Any]:
    if session['username'] != 'admin':
        abort(404)
    if request.method == 'POST':
        username : str = request.form.get('login_name', '')
        if not username in account_data.keys():
            return render_template('remove_account.html', message_error='Username is not an existing account')
        account_data.pop(username, None)
        shutil.rmtree(os.path.join(files_directory, username), True)
        save_account_data()
        return redirect(url_for('user_page'))
    return render_template('remove_account.html')

if __name__ == '__main__':
    if not os.path.isfile(os.path.join(files_directory, 'accounts.json')):
        save_account_data()
    load_account_data()
    if not os.path.isfile(os.path.join(files_directory, 'links.json')):
        save_links_data()
    load_links_data()
    try:
        app.run('0.0.0.0', 5000, True)
    except KeyboardInterrupt:
        pass
