import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, DateTime, Integer
from sqlalchemy.orm import scoped_session, sessionmaker

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
    repo = Column(String)
    status = Column(String)
    reason = Column(String)

    def to_dict(self):
        return dict(
                tree=self.tree,
                repo=self.repo,
                status=self.status,
                reason=self.reason)

class DbLog(DbBase):
    __tablename__ = 'log'
    id = Column(Integer, primary_key=True)
    tree = Column(String(32), nullable=False, index=True)
    when = Column(DateTime, nullable=False, index=True)
    who = Column(String, nullable=False)
    action = Column(String(16), nullable=False)
    reason = Column(String, nullable=False)

    def to_dict(self):
        return dict(
                tree=self.tree,
                when=self.when.strftime("%Y-%m-%dT%H:%M:%S%Z"),
                who=self.who,
                action=self.action,
                reason=self.reason)
