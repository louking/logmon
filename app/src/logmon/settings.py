'''
settings - define default, test and production settings

see http://flask.pocoo.org/docs/1.0/config/?highlight=production#configuration-best-practices

The list of monitored apps comes from /config/logapps.yml, which is a
read-only bind mount defined in docker-compose.yml.
'''

# standard
import os
import logging
import yaml
from dataclasses import dataclass, field

# homegrown
from loutilities.configparser import getitems

LOGAPPS_PATH = os.environ.get("LOGAPPS_PATH", "/config/logapps.yml")

@dataclass
class AppEntry:
    name: str
    log_dir: str
    # Filenames within log_dir.  Defaults keep the common convention where
    # both files live in the same directory.  Override in logapps.yml if
    # your files are named differently.
    app_log: str | None = None      # defaults to {name}.log  e.g. contracts.log
    access_log: str | None = None   # defaults to access.log
    alert_suppress_seconds: int | None = None   # None → use global default

    @property
    def app_log_path(self) -> str:
        return os.path.join(self.log_dir, self.app_log or f"{self.name}.log")

    @property
    def access_log_path(self) -> str:
        return os.path.join(self.log_dir, self.access_log or "access.log")

def _load_logapps() -> list[AppEntry]:
    try:
        with open(LOGAPPS_PATH) as fh:
            data = yaml.safe_load(fh) or {}
        apps = []
        for name, cfg in (data.get("apps") or {}).items():
            apps.append(AppEntry(
                name=name,
                log_dir=cfg["log_dir"],
                app_log=cfg.get("app_log"),
                access_log=cfg.get("access_log"),
                alert_suppress_seconds=cfg.get("alert_suppress_seconds"),
            ))
        return apps
    except FileNotFoundError:
        return []

class Config(object):
    DEBUG = False
    TESTING = False

    # default database
    # https://flask-sqlalchemy.palletsprojects.com/en/2.x/binds/
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_BINDS = {
        'users': 'sqlite:///:memory:',
    }

    # logging
    LOGGING_LEVEL_FILE = logging.INFO
    LOGGING_LEVEL_MAIL = logging.ERROR

    # flask-security configuration -- see https://pythonhosted.org/Flask-Security/configuration.html
    SECURITY_TRACKABLE = True
    SECURITY_DEFAULT_REMEMBER_ME = True

    # avoid warning
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # branding
    THISAPP_PRODUCTNAME = '<span class="brand-all"><span class="brand-left">lm</span><span class="brand-right">tility</span></span>'
    THISAPP_PRODUCTNAME_TEXT = 'lmtility'

    # --------------------------------------------------------- alert settings
    ALERT_RECIPIENTS: list[str] = os.environ.get("ALERT_RECIPIENTS", "").split(",")
    ALERT_SUPPRESS_SECONDS: int = int(os.environ.get("ALERT_SUPPRESS_SECONDS", 3600))

    # ------------------------------------------------------------ SNS
    SNS_TOPIC_ARNS_ALLOWED: list[str] = [
        t.strip() for t in os.environ.get("SNS_TOPIC_ARNS", "").split(",") if t.strip()
    ]

    # ---------------------------------------------------------- log apps
    # Loaded once at startup from the mounted YAML file.
    LOG_APPS: list[AppEntry] = field(default_factory=list)

    # --------------------------------------------------- live-tail ring buffer
    LOG_TAIL_LINES: int = int(os.environ.get("LOG_TAIL_LINES", 500))

class Testing(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False

    # need to set SERVER_NAME to something, else get a RuntimeError about not able to create URL adapter
    # must have following line in /etc/hosts or C:\Windows\System32\drivers\etc\hosts file
    #   127.0.0.1 dev.localhost
    SERVER_NAME = 'logmon.localhost'

    # need a default secret key - in production replace by config file
    SECRET_KEY = "<test secret key>"

    # need to allow logins in flask-security. see https://github.com/mattupstate/flask-security/issues/259
    LOGIN_DISABLED = False


class RealDb(Config):
    def __init__(self, configfiles):
        if type(configfiles) == str:
            configfiles = [configfiles]

        # connect to database based on configuration
        config = {}
        for configfile in configfiles:
            config.update(getitems(configfile, 'database'))
        dbuser = config['dbuser']
        with open(f'/run/secrets/appdb-password') as pw:
            password = pw.readline().strip()
        dbserver = config['dbserver']
        dbname = config['dbname']
        # app.logger.debug('using mysql://{uname}:*******@{server}/{dbname}'.format(uname=dbuser,server=dbserver,dbname=dbname))
        db_uri = 'mysql://{uname}:{pw}@{server}/{dbname}'.format(uname=dbuser, pw=password, server=dbserver,
                                                                 dbname=dbname)
        self.SQLALCHEMY_DATABASE_URI = db_uri
        
        # when user database is available, add bind
        if 'usersdbname' in config:
            # https://flask-sqlalchemy.palletsprojects.com/en/2.x/binds/
            usersdbuser = config['usersdbuser']
            with open(f'/run/secrets/users-password') as pw:
                userspassword = pw.readline().strip()
            usersdbserver = config['usersdbserver']
            usersdbname = config['usersdbname']
            usersdb_uri = f'mysql://{usersdbuser}:{userspassword}@{usersdbserver}/{usersdbname}'
            self.SQLALCHEMY_BINDS = {
                'users': usersdb_uri
            }

    @classmethod
    def load(cls, configfiles) -> "Config":
        """Return a fully-populated Config instance."""
        obj = cls(configfiles)
        obj.LOG_APPS = _load_logapps()
        return obj



class Development(RealDb):
    DEBUG = True


class Production(RealDb):
    pass


