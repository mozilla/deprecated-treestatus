#!/usr/bin/env python
import os
import treestatus.app, treestatus.model as model

def main():
    app = treestatus.app.wsgiapp({
        'here': os.curdir,
        'sqlalchemy.url': 'sqlite:///treestatus.db',
        'debug': True,
    })
    model.DbBase.metadata.create_all()
    app.run()

if __name__ == '__main__':
    main()
