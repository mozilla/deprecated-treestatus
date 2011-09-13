from datetime import datetime

from simplejson import dumps, loads
import memcache

import treestatus.model as model

import logging
log = logging.getLogger(__name__)

class Status:

    memcachePrefix = 'treestatus'
    defaultLogCache = 100

    def __init__(self):
        self.memcache = None

    def _mcGet(self, key, default=None):
        val = self.memcache.get(str('%s:%s' % (self.memcachePrefix, key)))
        if val is None:
            return default
        return loads(val)

    def _mcPut(self, key, val, expires=0):
        self.memcache.set(str('%s:%s' % (self.memcachePrefix, key)), dumps(val), time=expires)

    def _mcDelete(self, key):
        self.memcache.delete(str('%s:%s' % (self.memcachePrefix, key)))

    def getLogs(self, tree, limit=defaultLogCache):
        if self.memcache and limit == self.defaultLogCache:
            logs = self._mcGet('logs:%s:%s' % (tree, limit))
            if logs:
                return logs

        logs = []
        q = model.Session.query(model.DbLog).filter_by(tree=tree)
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

    def getTree(self, tree):
        if self.memcache:
            t = self._mcGet('tree:%s' % tree)
            if t:
                return t

            log.info("cache miss for %s", tree)

        t = model.Session.query(model.DbTree).get(tree)
        if t:
            t = t.to_dict()
        if self.memcache:
            self._mcPut('tree:%s' % tree, t, expires=60)

        return t

    def getTrees(self):
        if self.memcache:
            treenames = self._mcGet('trees')
            if treenames:
                trees = {}
                for t in treenames:
                    trees[t] = self.getTree(t)
                return trees

        trees = {}
        treenames = []
        for t in model.Session.query(model.DbTree):
            trees[t.tree] = t.to_dict()
            treenames.append(t.tree)
            if self.memcache:
                self._mcPut('tree:%s' % t.tree, trees[t.tree], expires=60)

        if self.memcache:
            log.info("cache miss for trees")
            self._mcPut('trees', treenames, expires=60)

        return trees

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

    def get_status(self, tree):
        return self.getTree(tree)

    def set_status(self, who, tree, status, reason, tags):
        session = request.session
        db_tree = session.query(model.DbTree).get(tree)
        db_tree.status = status
        db_tree.reason = reason
        self.log(tree, who, status, reason, tags)
        session.commit()
        # Update cache
        if self.memcache:
            self._mcPut('tree:%s' % tree, db_tree.to_dict(), expires=60)

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

def is_json():
    if 'application/json' in request.headers.get('Accept', ''):
        return True
    if request.args.get('format') == 'json':
        return True
    return False

@app.route('/')
def index():
    if is_json():
        return jsonify(status.getTrees())

    trees = [t for t in status.getTrees().values()]
    trees.sort(key=lambda t: t['tree'])

    resp = render_template('index.html', trees=trees)
    return resp

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/', methods=['POST'])
def add_or_set_trees():
    if not 'REMOTE_USER' in request.environ:
        flask.abort(401)

    if 'status' in request.form:
        if request.form.get('reason', None) is None:
            flask.abort(400, description="missing reason")

        tags = dumps(request.form.getlist('tags'))
        for tree in request.form.getlist('tree'):
            status.set_status(request.environ['REMOTE_USER'], tree, request.form['status'], request.form['reason'], tags)
    elif 'newtree' in request.form:
        if not request.form['newtree']:
            flask.abort(400)
        if request.form['newtree'] in status.getTrees():
            flask.abort(400)
        status.add_tree(request.environ['REMOTE_USER'], request.form['newtree'])
    return flask.redirect('/', 303)

@app.route('/login')
def login():
    if not 'REMOTE_USER' in request.environ:
        flask.abort(401)
    # TODO: Redirect them to where they were before
    return flask.redirect('/', 303)

@app.route('/logout')
def logout():
    if 'REMOTE_USER' in request.environ:
        flask.abort(401)
    # TODO: Redirect them to where they were before
    return flask.redirect('/', 303)

@app.route('/<tree>', methods=['GET'])
def get_tree(tree):
    t = status.getTree(tree)
    if not t:
        flask.abort(404)

    if is_json():
        return jsonify(t)

    resp = render_template('tree.html', tree=t, logs=status.getLogs(tree), loads=loads)
    return resp

@app.route('/<tree>/logs')
def get_logs(tree):
    t = status.getTree(tree)
    if not t:
        flask.abort(404)

    if request.args.get('all') == '1':
        logs = status.getLogs(tree, limit=None)
    else:
        logs = status.getLogs(tree)

    if is_json():
        resp = jsonify(dict(logs=logs))
    else:
        resp = make_response(dumps(logs, indent=2))
        resp.headers['Content-Type'] = 'text/plain'
    return resp

@app.route('/<tree>', methods=['POST'])
def update_tree(tree):
    if not 'REMOTE_USER' in request.environ:
        flask.abort(401)

    t = status.getTree(tree)
    if not t:
        flask.abort(404)

    if '_method' in request.form and request.form['_method'] == 'DELETE':
        return delete_tree(tree)

    if not 'reason' in request.form or not 'status' in request.form:
        flask.abort(400)

    # Update tree status
    tags = dumps(request.form.getlist('tags'))
    status.set_status(request.environ['REMOTE_USER'], tree, request.form['status'], request.form['reason'], tags)
    return flask.redirect(tree, 303)

@app.route('/<tree>', methods=['DELETE'])
def delete_tree(tree):
    if not 'REMOTE_USER' in request.environ:
        flask.abort(401)

    t = status.getTree(tree)
    if not t:
        flask.abort(404)

    # pretend this is a POST request; request.args doesn't read POST
    # parameters for DELETE calls
    request.environ['REQUEST_METHOD'] = 'POST'
    if not 'reason' in request.form:
        flask.abort(400)
    status.del_tree(request.environ['REMOTE_USER'], tree, request.form['reason'])
    return flask.redirect(tree, 303)

@app.before_request
def create_session():
    request.session = model.Session()

def wsgiapp(config, **kwargs):
    config.update(kwargs)
    model.setup(config)
    status.setup(config)
    app.debug = True
    logging.basicConfig(level=logging.INFO)
    return app
