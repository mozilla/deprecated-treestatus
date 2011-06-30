import os
from datetime import datetime
from threading import RLock

from simplejson import dumps
import web
from web.contrib.template import render_jinja

import treestatus.model as model

class Status:
    def __init__(self):
        # Mapping of tree name to DbTree dicts
        self.trees = {}
        # Mapping of tree name to last 100 log entries
        self.logs = {}

        self.lock = RLock()

    def setup(self):
        # Populate self.trees, self.logs
        for t in model.Session.query(model.DbTree):
            self.trees[t.tree] = t.to_dict()

        for t in self.trees:
            self.logs[t] = []
            # Load last 100 logs
            for l in model.Session.query(model.DbLog).filter_by(tree=t).order_by(model.DbLog.when.desc()).limit(100):
                self.logs[t].insert(0, l.to_dict())

    def log(self, tree, who, action, reason):
        l = model.DbLog()
        l.tree = tree
        l.who = who
        l.action = action
        l.when = datetime.now()
        l.reason = reason
        web.ctx.session.add(l)
        self.logs.setdefault(tree, []).append(l.to_dict())
        while len(self.logs[tree]) > 100:
            self.logs[tree].pop(0)

    def get_status(self, tree):
        return self.trees[tree]

    def set_status(self, who, tree, status, reason):
        with self.lock:
            session = web.ctx.session
            db_tree = session.query(model.DbTree).get(tree)
            db_tree.status = status
            db_tree.reason = reason
            self.log(tree, who, status, reason)
            session.commit()
            self.trees[tree] = db_tree.to_dict()

    def add_tree(self, who, tree):
        with self.lock:
            db_tree = model.DbTree()
            db_tree.tree = tree
            db_tree.status = "open"
            session = web.ctx.session
            session.add(db_tree)
            self.log(tree, who, 'added', 'Added new tree')
            session.commit()
            self.trees[tree] = db_tree.to_dict()

status = Status()

render = render_jinja('%s/templates' % os.path.dirname(__file__), encoding='utf-8')

class Base(object):
    @staticmethod
    def is_json():
        if 'application/json' in web.ctx.env.get('HTTP_ACCEPT'):
            return True
        if "format=json" in web.ctx.query:
            return True
        return False

class WebTrees(Base):
    def GET(self):
        if self.is_json():
            web.ctx.headers.append(('Content-Type', 'text/json'))
            return dumps(status.trees)
        web.ctx['headers'].append(('Content-Type', 'text/html'))
        return render.index(trees=status.trees)

    def POST(self):
        if not 'REMOTE_USER' in web.ctx.env:
            return web.Unauthorized()

        data = web.input()
        if 'action' not in data:
            return web.BadRequest()

        if data.action == 'closeall':
            for tree in status.trees:
                status.set_status(web.ctx.env['REMOTE_USER'], tree, 'closed', data.reason)
        elif data.action == 'newtree':
            if 'tree' not in data:
                return web.BadRequest()
            if not data.tree:
                return web.BadRequest()
            if data.tree in status.trees:
                return web.BadRequest()
            status.add_tree(web.ctx.env['REMOTE_USER'], data.tree)
        raise web.seeother('/')

class WebTree(Base):
    def GET(self, tree):
        if tree not in status.trees:
            raise web.notfound()

        if self.is_json():
            web.ctx.headers.append(('Content-Type', 'text/json'))
            return dumps(status.trees[tree])
        web.ctx['headers'].append(('Content-Type', 'text/html'))
        return render.tree(tree=status.trees[tree], logs=status.logs[tree], ctx=web.ctx)

    def POST(self, tree):
        if not 'REMOTE_USER' in web.ctx.env:
            return web.Unauthorized()

        # Update tree status
        if tree not in status.trees:
            raise web.notfound()

        data = web.input()
        if data.action == 'close':
            status.set_status(web.ctx.env['REMOTE_USER'], tree, 'closed', data.get('reason', None))
        elif data.action == 'open':
            status.set_status(web.ctx.env['REMOTE_USER'], tree, 'open', data.get('reason', None))
        raise web.seeother(tree)

class WebTreeLog(Base):
    def GET(self, tree):
        if tree not in status.trees:
            raise web.notfound()

        data = web.input()
        if 'all' in data and data.all == '1':
            logs = []
            for l in model.Session.query(model.DbLog).filter_by(tree=tree).order_by(model.DbLog.when.desc()):
                logs.append(l.to_dict())
        else:
            logs = status.logs[tree]

        if self.is_json():
            web.ctx.headers.append(('Content-Type', 'text/json'))
            return dumps(logs)
        else:
            web.ctx['headers'].append(('Content-Type', 'text/plain'))
            return dumps(logs, indent=2)

class WebRedirector:
    def GET(self):
        raise web.redirect(web.ctx.path.rstrip('/'))

class WebLogout:
    def GET(self):
        return web.Unauthorized()

def get_session(handler):
    web.ctx.session = model.Session()
    return handler()

urls = (
    '/', 'WebTrees',
    '/logout', 'WebLogout',
    '.*/$', 'WebRedirector', # Redirect urls that end with / to ones that don't
    '/([^/ ]+)', 'WebTree',
    '/([^/ ]+)/logs', 'WebTreeLog',
    )

def wsgiapp(config, **kwargs):
    config.update(kwargs)
    model.setup(config)
    status.setup()
    app = web.application(urls, globals())
    app.add_processor(get_session)
    return app.wsgifunc()
