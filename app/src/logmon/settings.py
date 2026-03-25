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
SECRETS_DIR  = os.environ.get("SECRETS_DIR",  "/run/secrets")

def _read_secret(name: str, default: str | None = None) -> str | None:
    """
    Read a value from a Docker secret file at /run/secrets/<name>.

    Raises RuntimeError for required secrets (default=None) that are missing.
    Returns default for optional secrets when the file is absent.
    """
    path = os.path.join(SECRETS_DIR, name)
    try:
        with open(path) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        if default is not None:
            return default
        raise RuntimeError(
            f"Required secret '{name}' not found at {path}. "
            f"Create the file or set SECRETS_DIR."
        )


def _inject_password(url: str, password: str) -> str:
    """
    Insert a password into a DB connection URL of the form:
      scheme://user@host/db   →   scheme://user:password@host/db

    The URL comes from an env var (username/host visible in docker inspect
    is acceptable); the password comes from a secret file (not visible).
    """
    if not url or not password:
        return url
    at = url.rfind("@")
    if at == -1:
        return url
    return url[:at] + ":" + password + url[at:]


# ------------------------------------------------------------------ AppEntry

@dataclass
class AppEntry:
    name: str
    log_dir: str
    # app_log accepts:
    #   None or omitted  → default filename ({name}.log inside log_dir)
    #   a filename/path  → bare name joined to log_dir, or absolute path used as-is
    #   False            → app log follower disabled (e.g. PHP/WordPress apps)
    # YAML: app_log: false  or  app_log: myapp.log  or omit entirely
    app_log: str | bool | None = None
    access_log: str | None = None
    alert_suppress_seconds: int | None = None   # None → use global default

    def __post_init__(self):
        # Normalise app_log so app_log_enabled works regardless of how the
        # value arrived (YAML bool, YAML string, direct construction):
        #   Python False  → keep as False  (disabled)
        #   string "false"→ False          (disabled)
        #   None/omitted  → keep as None   (use default filename)
        #   any string    → keep as-is     (explicit filename/path)
        if isinstance(self.app_log, str) and self.app_log.lower() == "false":
            self.app_log = False

    @property
    def app_log_enabled(self) -> bool:
        """True unless app_log was explicitly set to False (or the string 'false')."""
        return self.app_log is not False

    def _resolve(self, value: str | bool | None, default_filename: str) -> str:
        """Return an absolute path. Returns empty string if value is False (disabled)."""
        if value is False:
            return ""
        path = value if isinstance(value, str) else default_filename
        if os.path.isabs(path):
            return path
        return os.path.join(self.log_dir, path)

    @property
    def app_log_path(self) -> str:
        """Returns resolved path, or empty string when app log is disabled."""
        return self._resolve(self.app_log, f"{self.name}.log")

    @property
    def access_log_path(self) -> str:
        return self._resolve(self.access_log, "access.log")


def _load_logapps() -> list[AppEntry]:
    try:
        with open(LOGAPPS_PATH) as fh:
            data = yaml.safe_load(fh) or {}
        apps = []
        for name, cfg in (data.get("apps") or {}).items():
            apps.append(AppEntry(
                name=name,
                log_dir=cfg["log_dir"],
                # app_log: false in YAML → bool False → __post_init__ normalises to sentinel
                app_log=cfg.get("app_log", None),
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

    # -------------------------------------------------------------- flask-mail
    # commented items are in logmon.cfg; password is read from Docker secret file
    # MAIL_SERVER         = os.environ.get("MAIL_SERVER", "localhost")
    # MAIL_PORT           = int(os.environ.get("MAIL_PORT", 587))
    # MAIL_USE_TLS        = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    # MAIL_USERNAME       = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD       = _read_secret("mail-password", default="")
    # MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "logmon@example.com")

    # --------------------------------------------------------- alert settings
    ALERT_RECIPIENTS: list[str] = os.environ.get("ALERT_RECIPIENTS", "").split(",")
    ALERT_SUPPRESS_SECONDS: int = int(os.environ.get("ALERT_SUPPRESS_SECONDS", 3600))

    # ------------------------------------------------------------ SNS
    SNS_TOPIC_ARNS_ALLOWED: list[str] = [
        t.strip() for t in os.environ.get("SNS_TOPIC_ARNS", "").split(",") if t.strip()
    ]
    # Webhook shared secret — read from Docker secret file.
    # Include as ?key=<value> in the SNS HTTP subscription URL.
    # If the file is absent or the value is empty, key checking is disabled
    # (acceptable in development; not recommended in production).
    SNS_WEBHOOK_KEY: str | None = _read_secret("sns-webhook-key", default="") or None

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


