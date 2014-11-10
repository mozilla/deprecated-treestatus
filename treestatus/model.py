import os
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, Boolean
from sqlalchemy.orm import scoped_session, sessionmaker, relation
from sqlalchemy.engine.reflection import Inspector
import migrate.versioning.api
import migrate.exceptions
import logging

log = logging.getLogger(__name__)

migrate_schema = os.path.normpath(os.path.join(os.path.dirname(__file__), '../schema'))

DbBase = declarative_base()

Session = None


def setup(config):
    engine = sa.engine_from_config(config, pool_recycle=60)
    # Make sure we're up-to-date
    try:
        version = migrate.versioning.api.db_version(engine, migrate_schema)
        log.info("our db schema version is %s", version)
    except migrate.exceptions.DatabaseNotControlledError:
        # Our DB isn't under version control yet
        # Put it under version control
        # If we have a 'trees' table, it's version 1, otherwise we're version 0
        insp = Inspector.from_engine(engine)
        if "trees" in insp.get_table_names():
            version = 1
        else:
            version = 0
        log.info("putting tables under version control starting with version %s", version)
        migrate.versioning.api.version_control(engine, migrate_schema, version)
    version = migrate.versioning.api.upgrade(engine, migrate_schema)
    if version:
        log.info("upgraded db schema to %s", version)

    DbBase.metadata.bind = engine
    global Session
    Session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


class DbTree(DbBase):
    __tablename__ = 'trees'
    tree = Column(String(32), primary_key=True)
    status = Column(String(64), default="open", nullable=False)
    reason = Column(String(256), default="", nullable=False)
    message_of_the_day = Column(String(800), default="", nullable=False)

    def to_dict(self):
        return dict(
            tree=self.tree,
            status=self.status,
            reason=self.reason,
            message_of_the_day=self.message_of_the_day,
            )


class DbLog(DbBase):
    __tablename__ = 'log'
    id = Column(Integer, primary_key=True)
    tree = Column(String(32), nullable=False, index=True)
    when = Column(DateTime, nullable=False, index=True)
    who = Column(String(100), nullable=False)
    action = Column(String(16), nullable=False)
    reason = Column(String(256), nullable=False)
    tags = Column(String(256), nullable=False)

    def to_dict(self):
        return dict(
            tree=self.tree,
            when=self.when.strftime("%Y-%m-%dT%H:%M:%S%Z"),
            who=self.who,
            action=self.action,
            reason=self.reason,
            tags=self.tags,
            )


class DbToken(DbBase):
    __tablename__ = 'tokens'
    who = Column(String(100), nullable=False, primary_key=True)
    token = Column(String(100), nullable=False)

    @classmethod
    def delete(cls, who):
        q = cls.__table__.delete(cls.who == who)
        q.execute()

    @classmethod
    def get(cls, who):
        q = cls.__table__.select(cls.who == who)
        result = q.execute().fetchone()
        return result


class DbStatusStack(DbBase):
    __tablename__ = 'status_stacks'
    id = Column(Integer, primary_key=True)
    who = Column(String(100), nullable=False)
    reason = Column(String(256), nullable=False)
    when = Column(DateTime, nullable=False, index=True)
    status = Column(String(64), nullable=False)


class DbStatusStackTree(DbBase):
    __tablename__ = 'status_stack_trees'
    id = Column(Integer, primary_key=True)
    stack_id = Column(Integer, ForeignKey(DbStatusStack.id), index=True)
    tree = Column(String(32), nullable=False, index=True)
    last_state = Column(String(1024), nullable=False)

    stack = relation(DbStatusStack, backref='trees')


class DbUser(DbBase):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), index=True)
    is_admin = Column(Boolean, nullable=False, default=False)
    is_sheriff = Column(Boolean, nullable=False, default=False)

    @classmethod
    def get(cls, name):
        q = cls.__table__.select(cls.name == name)
        result = q.execute().fetchone()
        return result
