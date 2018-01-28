# E/PRO Backend API

- Setup for running on localhost:5000

```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ createdb eprodb
$ flask db init
$ flask db migrate
$ flask db upgrade
$ export FLASK_APP=app.py
```

- JWT
```bash
>>> import os
>>> os.urandom(24)
$ export SECRET_KEY='code generated above'
```

```bash
(venv)$ flask run
```