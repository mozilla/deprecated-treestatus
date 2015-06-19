from sqlalchemy import MetaData, Table, Column, String

meta = MetaData()


def upgrade(migrate_engine):
    meta.bind = migrate_engine
    trees = Table('trees', meta, autoload=True)
    tags = Column('tags', String(256), default="", server_default="", nullable=False)
    tags.create(trees)

    status_stacks = Table('status_stacks', meta, autoload=True)
    tags = Column('tags', String(256), default="", server_default="", nullable=False)
    tags.create(status_stacks)
    


def downgrade(migrate_engine):
    meta.bind = migrate_engine
    trees = Table('trees', meta, autoload=True)
    trees.c.tags.drop()

    status_stacks = Table('status_stacks', meta, autoload=True)
    status_stacks.c.tags.drop()
