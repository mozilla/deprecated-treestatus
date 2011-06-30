from treestatus import model

def setup_app(command, conf, vars):
    model.setup(conf)
    model.DbBase.metadata.create_all()
