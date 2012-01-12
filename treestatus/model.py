import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, Boolean
from sqlalchemy.orm import scoped_session, sessionmaker, relation

DbBase = declarative_base()

Session = None

def setup(config):
    engine = sa.engine_from_config(config)
    DbBase.metadata.bind = engine
    global Session
    Session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

class DbTree(DbBase):
    __tablename__ = 'trees'
    tree = Column(String(32), primary_key=True)
    status = Column(String, default="open", nullable=False)
    reason = Column(String, default="", nullable=False)

    def to_dict(self):
        return dict(
                tree=self.tree,
                status=self.status,
                reason=self.reason,
                )

class DbLog(DbBase):
    __tablename__ = 'log'
    id = Column(Integer, primary_key=True)
    tree = Column(String(32), nullable=False, index=True)
    when = Column(DateTime, nullable=False, index=True)
    who = Column(String, nullable=False)
    action = Column(String(16), nullable=False)
    reason = Column(String, nullable=False)
    tags = Column(String, nullable=False)

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
    who = Column(String, nullable=False, primary_key=True)
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
    who = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    when = Column(DateTime, nullable=False, index=True)
    status = Column(String, nullable=False)

class DbStatusStackTree(DbBase):
    __tablename__ = 'status_stack_trees'
    id = Column(Integer, primary_key=True)
    stack_id = Column(Integer, ForeignKey(DbStatusStack.id), index=True)
    tree = Column(String(32), nullable=False, index=True)
    last_state = Column(String, nullable=False)

    stack = relation(DbStatusStack, backref='trees')

class DbUser(DbBase):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String, index=True)
    is_admin = Column(Boolean, nullable=False, default=False)
    is_sheriff = Column(Boolean, nullable=False, default=False)

    @classmethod
    def get(cls, name):
        q = cls.__table__.select(cls.name == name)
        result = q.execute().fetchone()
        return result
