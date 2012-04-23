import os, site
my_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
site.addsitedir(my_dir)
site.addsitedir(os.path.join(my_dir, "vendor/lib/python"))

from datetime import datetime
import urllib
from binascii import b2a_base64

from simplejson import dumps, loads
import memcache
from repoze.who.config import make_middleware_with_config
import sqlalchemy as sa

import treestatus.model as model

import logging
log = logging.getLogger(__name__)

class Status:

    memcachePrefix = 'treestatus'
    defaultLogCache = 100

    def __init__(self):
        self.memcache = None

    ###
    # memcache helpers
    ###
    def _mcKey(self, key):
        key = key.encode('base64').rstrip('=\n')
        return str('%s:%s' % (self.memcachePrefix, key))

    def _mcGet(self, key, default=None):
        key = self._mcKey(key)
        val = self.memcache.get(key)
        if val is None:
            return default
        return loads(val)

    def _mcPut(self, key, val, expires=0):
        key = self._mcKey(key)
        self.memcache.set(key, dumps(val), time=expires)

    def _mcDelete(self, key):
        key = self._mcKey(key)
        self.memcache.delete(key)

    ###
    # app helpers
    ###
    def setup(self, config):
        # Check if we should be connecting to memcached
        if 'memcached.servers' in config:
            self.memcache = memcache.Client(config['memcached.servers'].split(","))

    def log(self, tree, who, action, reason, tags=""):
        l = model.DbLog()
        l.tree = tree
        l.who = who
        l.action = action
        l.when = datetime.now()
        l.reason = reason
        l.tags = tags
        request.session.add(l)
        if self.memcache:
            # Flush the cached logs
            self._mcDelete('logs:%s:%s' % (tree, self.defaultLogCache))

    ###
    # authentication helpers
    ###
    def get_user(self, who):
        u = model.DbUser.get(who)
        return u

    def make_token(self, who):
        # Delete any previous token we have
        model.DbToken.delete(who)

        token = model.DbToken()
        token.who = who
        token.token = b2a_base64(os.urandom(64)).rstrip('=\n')
        session = request.session
        session.add(token)
        session.commit()
        return token.token

    def delete_token(self, who):
        model.DbToken.delete(who)

    def validate_token(self, who, token):
        t = model.DbToken.get(who)
        if not t:
            return False
        return t.token == token

    def get_token(self, who):
        t = model.DbToken.get(who)
        if not t:
            return ''
        return t.token

    ###
    # methods to serve url requests
    ###
    def get_logs(self, tree, limit=defaultLogCache):
        if self.memcache and limit == self.defaultLogCache:
            logs = self._mcGet('logs:%s:%s' % (tree, limit))
            if logs:
                return logs

        logs = []
        q = request.session.query(model.DbLog).filter_by(tree=tree)
        q = q.order_by(model.DbLog.when.desc())
        if limit:
            q = q.limit(limit)
        for l in q:
            d = l.to_dict()
            try:
                d['tags'] = loads(d['tags'])
            except:
                pass
            logs.append(d)

        if self.memcache and limit == self.defaultLogCache:
            log.info("cache miss for logs:%s:%s", tree, limit)
            self._mcPut('logs:%s:%s' % (tree, limit), logs, expires=60)
        return logs

    def get_tree(self, tree):
        if self.memcache:
            t = self._mcGet('tree:%s' % tree)
            if t:
                return t

            log.info("cache miss for %s", tree)

        t = request.session.query(model.DbTree).get(tree)
        if t:
            t = t.to_dict()
        if self.memcache:
            self._mcPut('tree:%s' % tree, t, expires=60)

        return t

    def get_trees(self):
        if self.memcache:
            treenames = self._mcGet('trees')
            if treenames:
                trees = {}
                for t in treenames:
                    trees[t] = self.get_tree(t)
                return trees

        trees = {}
        treenames = []
        for t in request.session.query(model.DbTree):
            trees[t.tree] = t.to_dict()
            treenames.append(t.tree)
            if self.memcache:
                self._mcPut('tree:%s' % t.tree, trees[t.tree], expires=60)

        if self.memcache:
            log.info("cache miss for trees")
            self._mcPut('trees', treenames, expires=60)

        return trees

    def get_status(self, tree):
        return self.get_tree(tree)

    def set_status(self, who, tree, status, reason, tags, flush_stack=True):
        session = request.session
        db_tree = session.query(model.DbTree).get(tree)
        db_tree.status = status
        db_tree.reason = reason
        if flush_stack:
            for s in session.query(model.DbStatusStackTree).filter_by(tree=tree):
                stack = s.stack
                stack.trees.remove(s)
                if not stack.trees:
                    session.delete(stack)
                session.delete(s)
        self.log(tree, who, status, reason, tags)
        session.commit()
        # Update cache
        if self.memcache:
            self._mcPut('tree:%s' % tree, db_tree.to_dict(), expires=60)

    def restore_status(self, who, stack_id):
        log.info("%s is restoring stack %s", who, stack_id)
        session = request.session
        stack = session.query(model.DbStatusStack).get(stack_id)

        for tree in stack.trees:
            # Restore its state
            last_state = loads(tree.last_state)
            self.set_status(who, tree.tree, last_state['status'], last_state['reason'], '', flush_stack=False)

        # Delete everything
        for tree in stack.trees:
            session.delete(tree)
        session.delete(stack)
        session.commit()

    def remember_state(self, who, trees, status, reason):
        if not trees:
            return
        stack = model.DbStatusStack()
        stack.who = who
        stack.reason = reason
        stack.when = datetime.now()
        stack.status = status
        session = request.session
        session.add(stack)
        log.debug("Remembering %s", stack)

        for tree in trees:
            s = model.DbStatusStackTree()
            s.stack = stack
            s.tree = tree
            s.last_state = dumps(session.query(model.DbTree).get(tree).to_dict())
            session.add(s)

        session.commit()

    def get_remembered_states(self):
        session = request.session
        stacks = session.query(model.DbStatusStack).order_by(model.DbStatusStack.when.desc())
        return list(stacks)

    def add_tree(self, who, tree):
        db_tree = model.DbTree()
        db_tree.tree = tree
        db_tree.status = "open"
        session = request.session
        session.add(db_tree)
        self.log(tree, who, 'added', 'Added new tree')
        session.commit()
        if self.memcache:
            # Flush the cached list of trees
            self._mcDelete('trees')

    def del_tree(self, who, tree, reason):
        session = request.session
        db_tree = session.query(model.DbTree).get(tree)
        session.delete(db_tree)
        self.log(tree, who, 'deleted', reason)
        session.commit()
        if self.memcache:
            self._mcDelete('tree:%s' % tree)
            self._mcDelete('trees')

status = Status()

import flask
from flask import Flask, request, make_response, render_template, jsonify
app = Flask(__name__)

@app.template_filter('urlencode')
def urlencode(s):
    return urllib.quote(s, '')

def urldecode(s):
    return urllib.unquote(s)

def is_json():
    if 'application/json' in request.headers.get('Accept', ''):
        return True
    if request.args.get('format') == 'json':
        return True
    return False

def validate_write_request():
    who = request.environ.get('REMOTE_USER')
    if who is None:
        flask.abort(401)

    token = request.form.get('token', None)
    if token is None:
        log.info("Couldn't find token in request")
        flask.abort(403)

    if not status.validate_token(who, token):
        log.info("Couldn't validate token for user")
        flask.abort(403)

    u = status.get_user(who)
    if not u or not (u.is_sheriff or u.is_admin):
        log.info("User isn't allowed to do that")
        flask.abort(403)

def get_token():
    if 'REMOTE_USER' in request.environ:
        return status.get_token(request.environ['REMOTE_USER'])
    return ''

@app.route('/')
def index():
    if is_json():
        return jsonify(status.get_trees())

    trees = [t for t in status.get_trees().values()]
    trees.sort(key=lambda t: t['tree'])

    stacks = status.get_remembered_states()

    if 'REMOTE_USER' in request.environ:
        user = status.get_user(request.environ['REMOTE_USER'])
    else:
        user = None

    resp = make_response(render_template('index.html', trees=trees, token=get_token(), stacks=stacks, user=user))
    resp.headers['Cache-Control'] = 'max-age=30'
    resp.headers['Vary'] = 'Cookie'
    if '?nc' in request.url:
        resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/help')
def help():
    resp = make_response(render_template('help.html'))
    resp.headers['Cache-Control'] = 'max-age=600'
    return resp

@app.route('/login')
def login():
    who = request.environ.get('REMOTE_USER')

    if who is None:
        flask.abort(401)

    u = status.get_user(who)
    if not u or not (u.is_admin or u.is_sheriff):
        log.info("%s is not allowed", who)
        status.delete_token(who)
        resp = make_response(render_template('badlogin.html'), 403)
        # Force the user to logout
        if 'repoze.who.api' in request.environ:
            repoze_api = request.environ['repoze.who.api']
            resp.headers.extend(repoze_api.logout())
        return resp

    token = status.make_token(who)

    # TODO: Redirect them to where they were before
    resp = make_response(flask.redirect('/?nc', 303))
    # Include the token in the headers so scripts can re-use it
    resp.headers['X-Treestatus-Token'] = token
    return resp

@app.route('/logout')
def logout():
    if 'REMOTE_USER' in request.environ:
        status.delete_token(request.environ['REMOTE_USER'])

        # We can log out directly if we're using repoze.who
        if 'repoze.who.api' in request.environ:
            repoze_api = request.environ['repoze.who.api']
            resp = make_response(flask.redirect('/?nc', 303))
            resp.headers.extend(repoze_api.logout())
            return resp

        flask.abort(401)
    return flask.redirect('/?nc', 303)

@app.route('/<path:tree>', methods=['GET'])
def get_tree(tree):
    tree = urldecode(tree)
    t = status.get_tree(tree)
    if not t:
        flask.abort(404)

    if is_json():
        return jsonify(t)

    resp = make_response(render_template('tree.html', tree=t, logs=status.get_logs(tree),
            loads=loads, token=get_token()))
    resp.headers['Cache-Control'] = 'max-age=30'
    resp.headers['Vary'] = 'Cookie'
    if '?nc' in request.url:
        resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/<path:tree>/logs', methods=['GET'])
def get_logs(tree):
    t = status.get_tree(tree)
    if not t:
        flask.abort(404)

    if request.args.get('all') == '1':
        logs = status.get_logs(tree, limit=None)
    else:
        logs = status.get_logs(tree)

    if is_json():
        resp = jsonify(dict(logs=logs))
    else:
        resp = make_response(dumps(logs, indent=2))
        resp.headers['Content-Type'] = 'text/plain'
    resp.headers['Cache-Control'] = 'max-age=30'
    return resp

@app.route('/users', methods=['GET'])
def show_users():
    if 'REMOTE_USER' not in request.environ:
        log.debug("not logged in")
        flask.abort(403)

    u = status.get_user(request.environ['REMOTE_USER'])
    if not u or not u.is_admin:
        log.debug("%s is not an admin", u)
        flask.abort(403)

    users = request.session.query(model.DbUser)
    resp = make_response(render_template('users.html', user=u, users=users, token=get_token()))
    resp.headers['Cache-Control'] = 'max-age=30'
    resp.headers['Vary'] = 'Cookie'
    if '?nc' in request.url:
        resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/users', methods=['POST'])
def modify_users():
    if 'REMOTE_USER' not in request.environ:
        flask.abort(403)

    u = status.get_user(request.environ['REMOTE_USER'])
    if not u or not u.is_admin:
        flask.abort(403)

    validate_write_request()

    session = request.session

    log.info("form data: %s", request.form)

    # Delete users
    for k in request.form.keys():
        if not k.startswith("delete:"):
            continue
        uid = k[len("delete:"):]
        log.info("deleting %s", uid)
        u = session.query(model.DbUser).filter_by(id=uid).one()
        if u:
            session.delete(u)

    # Add users
    if request.form.get('newuser'):
        u = model.DbUser()
        u.name = request.form.get('newuser')
        u.is_admin = False
        u.is_sheriff = False
        session.add(u)

    # Remove admin privs
    for uid in request.form.getlist('was_admin'):
        if not uid in request.form.getlist('admin'):
            u = session.query(model.DbUser).filter_by(id=uid).one()
            if not u:
                continue
            u.is_admin = False

    # Add admin privs
    for uid in request.form.getlist('admin'):
        u = session.query(model.DbUser).filter_by(id=uid).one()
        if not u:
            continue
        u.is_admin = True

    # Remove sheriff privs
    for uid in request.form.getlist('was_sheriff'):
        if not uid in request.form.getlist('sheriff'):
            u = session.query(model.DbUser).filter_by(id=uid).one()
            if not u:
                continue
            u.is_sheriff = False

    # Add sheriff privs
    for uid in request.form.getlist('sheriff'):
        u = session.query(model.DbUser).filter_by(id=uid).one()
        if not u:
            continue
        u.is_sheriff = True

    session.commit()

    return flask.redirect('/users?nc', 303)

@app.route('/', methods=['POST'])
def add_or_set_trees():
    validate_write_request()

    if request.form.get('restore'):
        # Restore stacked status
        status.restore_status(request.environ['REMOTE_USER'], request.form['restore'])

    if request.form.get('status'):
        if request.form.get('reason', None) is None:
            flask.abort(400, description="missing reason")

        tags = dumps(request.form.getlist('tags'))
        trees = request.form.getlist('tree')
        if request.form.get('remember') == 'remember':
            flush_stack = False
            status.remember_state(request.environ['REMOTE_USER'], trees, request.form['status'], request.form['reason'])
        else:
            flush_stack = True

        for tree in trees:
            status.set_status(request.environ['REMOTE_USER'], tree, request.form['status'], request.form['reason'], tags, flush_stack)

    if request.form.get('newtree'):
        if request.form['newtree'] not in status.get_trees():
            # We don't have this yet, so go create it!
            status.add_tree(request.environ['REMOTE_USER'], request.form['newtree'])
    return flask.redirect('/?nc', 303)

@app.route('/<path:tree>', methods=['POST'])
def update_tree(tree):
    validate_write_request()

    t = status.get_tree(tree)
    if not t:
        flask.abort(404)

    if '_method' in request.form and request.form['_method'] == 'DELETE':
        return delete_tree(tree)

    if not 'reason' in request.form or not 'status' in request.form:
        flask.abort(400)

    # Update tree status
    tags = dumps(request.form.getlist('tags'))
    status.set_status(request.environ['REMOTE_USER'], tree, request.form['status'], request.form['reason'], tags)
    return flask.redirect("/?nc" + tree, 303)

@app.route('/<path:tree>', methods=['DELETE'])
def delete_tree(tree):
    validate_write_request()

    t = status.get_tree(tree)
    if not t:
        flask.abort(404)

    # pretend this is a POST request; request.args doesn't read POST
    # parameters for DELETE calls
    request.environ['REQUEST_METHOD'] = 'POST'
    if not 'reason' in request.form:
        log.info("bad request; missing reason")
        flask.abort(400)
    status.del_tree(request.environ['REMOTE_USER'], tree, request.form['reason'])
    return flask.redirect("/" + tree, 303)

@app.before_request
def create_session():
    request.session = model.Session()

import os, time
_started = time.asctime()
@app.after_request
def close_session(response):
    request.session.close()
    response.headers['x-pid'] = str(os.getpid())
    response.headers['x-started'] = str(_started)
    return response

@app.errorhandler(sa.exc.InvalidRequestError)
def handle_db_error(e):
    request.session.close()
    raise e

def wsgiapp(config, **kwargs):
    config.update(kwargs)
    model.setup(config)
    status.setup(config)
    app.debug = config.get('debug')
    configfile = my_dir + "/who.ini"
    app.wsgi_app = make_middleware_with_config(app.wsgi_app, config, config.get('who_config', configfile))
    logging.basicConfig(level=logging.DEBUG)
    return app
