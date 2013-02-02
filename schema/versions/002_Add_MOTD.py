from sqlalchemy import MetaData, Table, Column, String

meta = MetaData()


def upgrade(migrate_engine):
    meta.bind = migrate_engine
    trees = Table('trees', meta, autoload=True)
    motd = Column('message_of_the_day', String(800), default="", server_default="", nullable=False)
    motd.create(trees)


def downgrade(migrate_engine):
    meta.bind = migrate_engine
    trees = Table('trees', meta, autoload=True)
    trees.c.message_of_the_day.drop()
