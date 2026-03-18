'''
nav - navigation
======================
define navigation bar based on privileges
'''

# standard

# pypi
from flask import g, current_app, url_for, request
import collections
collections.MutableMapping = collections.abc.MutableMapping # https://stackoverflow.com/a/78863584/799921
from flask_nav import Nav
from flask_nav.elements import Navbar, View, Subgroup, Link, Separator
from flask_nav.renderers import SimpleRenderer
from dominate import tags
from flask_security import current_user
from slugify import slugify

# homegrown
from .version import __docversion__
from loutilities.user.roles import ROLE_SUPER_ADMIN

thisnav = Nav()

@thisnav.renderer()
class NavRenderer(SimpleRenderer):
    '''
    this generates nav_renderer renderer, referenced in the jinja2 code which builds the nav
    '''
    def visit_Subgroup(self, node):
        # 'a' tag required by smartmenus
        title = tags.a(node.title, href="#")
        group = tags.ul(_class='subgroup')

        if node.active:
            title.attributes['class'] = 'active'

        for item in node.items:
            group.add(tags.li(self.visit(item)))

        return [title, group]

@thisnav.navigation()
def nav_menu():
    navbar = Navbar('nav_menu')

    contexthelp = {}
    class add_view():
        def __init__(self, basehelp):
            self.basehelp = basehelp.format(docversion=__docversion__)

        def __call__(self, navmenu, text, endpoint, **kwargs):
            prelink = kwargs.pop('prelink', None)
            navmenu.items.append(View(text, endpoint, **kwargs))
            contexthelp[url_for(endpoint, **kwargs)] = self.basehelp + slugify(text + ' view')
            if not prelink:
                contexthelp[url_for(endpoint, **kwargs)] = self.basehelp + slugify(text + ' view')
            else:
                contexthelp[url_for(endpoint, **kwargs)] = self.basehelp + slugify(prelink + ' ' + text + ' view')

        def nomenu_help(self, text, endpoint, **kwargs):
            prelink = kwargs.pop('prelink', None)
            if not prelink:
                contexthelp[url_for(endpoint, **kwargs)] = self.basehelp + slugify(text + ' view')
            else:
                contexthelp[url_for(endpoint, **kwargs)] = self.basehelp + slugify(prelink + ' ' + text + ' view')


    leadership_superadmin_view = add_view('https://logmon.readthedocs.io/en/{docversion}/super-admin-reference.html#')

    if current_user.is_authenticated:
        if current_user.has_role(ROLE_SUPER_ADMIN):
            navbar.items.append(View('Dashboard', 'dashboard.index'))

        # superadmin stuff
            leadership_superadmin_view(navbar, 'Users', 'userrole.users')
            
            userroles = Subgroup('Super')
            navbar.items.append(userroles)

            leadership_superadmin_view(userroles, 'Users', 'userrole.users')
            leadership_superadmin_view(userroles, 'Roles', 'userrole.roles')
            leadership_superadmin_view(userroles, 'Applications', 'userrole.applications')

            navbar.items.append(View('My Account', 'security.change_password'))
            userroles.items.append(View('Debug', 'admin.debug'))

        # finally for non ROLE_SUPER_ADMIN
        else:
            navbar.items.append(View('My Account', 'security.change_password'))

    else:
        navbar.items.append(View('Home', 'frontend.home'))

    # navbar.items.append(View('About', 'admin.sysinfo'))
    if request.path in contexthelp:
        navbar.items.append(Link('Help', contexthelp[request.path]))

    return navbar

thisnav.init_app(current_app)
