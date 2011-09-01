from __future__ import with_statement
import os
from datetime import datetime

from simplejson import dumps, loads
import web
from web.contrib.template import render_jinja
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
            logs.append(l.to_dict())

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

    def log(self, tree, who, action, reason):
        l = model.DbLog()
        l.tree = tree
        l.who = who
        l.action = action
        l.when = datetime.now()
        l.reason = reason
        web.ctx.session.add(l)
        if self.memcache:
            # Flush the cached logs
            self._mcDelete('logs:%s:%s' % (tree, self.defaultLogCache))

    def get_status(self, tree):
        return self.getTree(tree)

    def set_status(self, who, tree, status, reason):
        session = web.ctx.session
        db_tree = session.query(model.DbTree).get(tree)
        db_tree.status = status
        db_tree.reason = reason
        self.log(tree, who, status, reason)
        session.commit()
        # Update cache
        if self.memcache:
            self._mcPut('tree:%s' % tree, db_tree.to_dict(), expires=60)

    def add_tree(self, who, tree):
        db_tree = model.DbTree()
        db_tree.tree = tree
        db_tree.status = "open"
        session = web.ctx.session
        session.add(db_tree)
        self.log(tree, who, 'added', 'Added new tree')
        session.commit()
        if self.memcache:
            # Flush the cached list of trees
            self._mcDelete('trees')

    def del_tree(self, who, tree, reason):
        session = web.ctx.session
        db_tree = session.query(model.DbTree).get(tree)
        session.delete(db_tree)
        self.log(tree, who, 'deleted', reason)
        session.commit()
        if self.memcache:
            self._mcDelete('tree:%s' % tree)
            self._mcDelete('trees')

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
            return dumps(status.getTrees())
        web.ctx['headers'].append(('Content-Type', 'text/html'))
        trees = [t for t in status.getTrees().values()]
        trees.sort(key=lambda t: t['tree'])
        return render.index(trees=trees, ctx=web.ctx)

    def POST(self):
        if not 'REMOTE_USER' in web.ctx.env:
            return web.Unauthorized()

        data = web.input()
        if 'status' in data:
            for tree in status.getTrees():
                status.set_status(web.ctx.env['REMOTE_USER'], tree, data.status, data.reason)
        elif 'newtree' in data:
            if not data.newtree:
                return web.BadRequest()
            if data.newtree in status.getTrees():
                return web.BadRequest()
            status.add_tree(web.ctx.env['REMOTE_USER'], data.newtree)
        raise web.seeother('/')

class WebTree(Base):
    def GET(self, tree):
        t = status.getTree(tree)
        if not t:
            raise web.notfound()

        if self.is_json():
            web.ctx.headers.append(('Content-Type', 'text/json'))
            return dumps(t)
        web.ctx['headers'].append(('Content-Type', 'text/html'))
        return render.tree(tree=t, logs=status.getLogs(tree), ctx=web.ctx)

    def POST(self, tree):
        if not 'REMOTE_USER' in web.ctx.env:
            return web.Unauthorized()

        t = status.getTree(tree)
        if not t:
            raise web.notfound()

        data = web.input()
        if '_method' in data and data._method == 'DELETE':
            return self.DELETE(tree)

        if not 'reason' in data or not 'status' in data:
            raise web.BadRequest()

        # Update tree status
        status.set_status(web.ctx.env['REMOTE_USER'], tree, data.status, data.reason)
        raise web.seeother(tree)

    def DELETE(self, tree):
        if not 'REMOTE_USER' in web.ctx.env:
            return web.Unauthorized()

        t = status.getTree(tree)
        if not t:
            raise web.notfound()

        # pretend this is a POST request; web.input() doesn't read POST
        # parameters for DELETE calls
        web.ctx.env['REQUEST_METHOD'] = 'POST'
        data = web.input()
        if not data or 'reason' not in data:
            raise web.BadRequest()
        status.del_tree(web.ctx.env['REMOTE_USER'], tree, data.reason)
        raise web.seeother(tree)

class WebTreeLog(Base):
    def GET(self, tree):
        if tree not in status.trees:
            raise web.notfound()

        data = web.input()
        if not ('all' in data and data.all == '1'):
            logs = status.getLogs(tree, limit=None)
        else:
            logs = status.getLogs(tree)

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

class WebLogin:
    def GET(self):
        if not 'REMOTE_USER' in web.ctx.env:
            return web.Unauthorized()
        # TODO: Redirect them to where they were before
        return web.seeother("/")

class WebHelp:
    def GET(self):
        return render.help()

def get_session(handler):
    web.ctx.session = model.Session()
    return handler()

urls = (
    '/', 'WebTrees',
    '/logout', 'WebLogout',
    '/login', 'WebLogin',
    '/help', 'WebHelp',
    '.*/$', 'WebRedirector', # Redirect urls that end with / to ones that don't
    '/([^/ ]+)', 'WebTree',
    '/([^/ ]+)/logs', 'WebTreeLog',
    )

def wsgiapp(config, **kwargs):
    config.update(kwargs)
    model.setup(config)
    status.setup(config)
    app = web.application(urls, globals())
    app.add_processor(get_session)
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    return app.wsgifunc()
