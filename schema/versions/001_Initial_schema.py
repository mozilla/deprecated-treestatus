from sqlalchemy import MetaData, Table, Column, String, Integer, DateTime, Boolean, ForeignKey
#from migrate import *

meta = MetaData()

trees = Table(
    'trees', meta,
    Column('tree', String(32), primary_key=True),
    Column('status', String(64), default="open", nullable=False),
    Column('reason', String(256), default="", nullable=False),
)

log = Table(
    'log', meta,
    Column('id', Integer, primary_key=True),
    Column('tree', String(32), nullable=False, index=True),
    Column('when', DateTime, nullable=False, index=True),
    Column('who', String(100), nullable=False),
    Column('action', String(16), nullable=False),
    Column('reason', String(256), nullable=False),
    Column('tags', String(256), nullable=False),
)

tokens = Table(
    'tokens', meta,
    Column('who', String(100), nullable=False, primary_key=True),
    Column('token', String(100), nullable=False),
)

status_stacks = Table(
    'status_stacks', meta,
    Column('id', Integer, primary_key=True),
    Column('who', String(100), nullable=False),
    Column('reason', String(256), nullable=False),
    Column('when', DateTime, nullable=False, index=True),
    Column('status', String(64), nullable=False),
)

status_stack_trees = Table(
    'status_stack_trees', meta,
    Column('id', Integer, primary_key=True),
    Column('stack_id', Integer, ForeignKey(status_stacks.c.id), index=True),
    Column('tree', String(32), nullable=False, index=True),
    Column('last_state', String(1024), nullable=False),
)

users = Table(
    'users', meta,
    Column('id', Integer, primary_key=True),
    Column('name', String(100), index=True),
    Column('is_admin', Boolean, nullable=False, default=False),
    Column('is_sheriff', Boolean, nullable=False, default=False),
)


def upgrade(migrate_engine):
    meta.bind = migrate_engine
    for t in trees, log, tokens, status_stacks, status_stack_trees, users:
        t.create()


def downgrade(migrate_engine):
    meta.bind = migrate_engine
    for t in trees, log, tokens, status_stacks, status_stack_trees, users:
        t.drop()
