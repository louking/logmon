'''
userrole - specific user/role management for this application

This is needed to update local database tables when using common database for single sign-on
'''

# homegrown
from logmon import user_datastore
# from ...model import update_local_tables
from ...version import __docversion__
from loutilities.user.views.userrole import UserView, RoleView
from loutilities.user.roles import ROLE_SUPER_ADMIN

orgadminguide = 'https://logmon.readthedocs.io/en/{docversion}/organization-admin-guide.html'.format(docversion=__docversion__)
superadminguide = 'https://logmon.readthedocs.io/en/{docversion}/super-admin-guide.html'.format(docversion=__docversion__)

user_view = UserView(
    pagename='users',
    user_datastore=user_datastore,
    roles_accepted=[ROLE_SUPER_ADMIN],
    endpoint='userrole.users',
    rule='/users',
    templateargs={'adminguide': orgadminguide},
)
user_view.register()

class LocalRoleView(RoleView):
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        args = dict(
            templateargs={'adminguide': superadminguide},
        )
        args.update(kwargs)

        # initialize inherited class, and a couple of attributes
        super().__init__(**args)

    # def editor_method_postcommit(self, form):
    #     update_local_tables()
role_view = LocalRoleView()
role_view.register()
