import itertools
from Role import Role
from User import User
from Resource import Resource
from Action import Action

roles = {}
users = {}
resources = {}


# Getter Methods
def get_roles():
    ''' Get roles currently active.'''
    return roles


def get_users():
    ''' Get users currently registered '''
    return users


def get_resources():
    ''' Get resources currently managed '''
    return resources


# Role Management
def are_valid_roles(role_names):
    ''' Checks if role_names map to existing roles '''
    return set(role_names).issubset(roles.keys())


def add_role(role_name):
    ''' Creates a new role '''
    if not are_valid_roles([role_name]):
        roles[role_name] = Role(role_name)
        return True
    else:
        return False


# User Management
def is_valid_user(user_name):
    ''' Checks if user_name maps to an existing role '''
    return user_name in users


def add_user(user_name, role_names):
    ''' Creates a new role '''
    if are_valid_roles(role_names) and not is_valid_user(user_name):
        users[user_name] = User(user_name, [roles[role_name] for role_name in role_names])
        return True
    else:
        return False


def add_role_to_user(user_name, role_name):
    ''' Adds an existing role to an existing user '''
    if is_valid_user(user_name) and are_valid_roles([role_name]):
        users[user_name].roles.append(roles[role_name])
        return True
    else:
        return False


# Resource Management
def is_valid_resource(resource_name):
    ''' Checks if resource name maps to a managed resource '''
    return resource_name in resources


def are_valid_actions(actions):
    ''' Check if action is present in list of supported actions '''
    return set(actions).issubset(Action)


def add_resource_with_access_map(resource_name, actions):
    ''' Add a resource with a dictionary of role names and supported actions '''
    if are_valid_roles(actions.keys()) and not is_valid_resource(resource_name) \
    and are_valid_actions(itertools.chain.from_iterable(actions.values())):
        resources[resource_name] = Resource(resource_name, actions)
        return True
    else:
        return False


def add_resource(resource_name, role_name, actions):
    ''' Create a resource with actions for a specfied role_name '''
    return add_resource_with_access_map(resource_name, {role_name: actions})


def add_access_to_resource(resource_name, role_name, actions):
    ''' Add access rights to resource '''
    if are_valid_roles([role_name]) and is_valid_resource(resource_name) \
    and are_valid_actions(actions):
        resources[resource_name].add_permission(roles[role_name], actions)
        return True
    else:
        return False


def is_action_authorized(resource_name, user_name, action):
    ''' Given a user, action type and resource system should be able to tell
        whether user has access or not '''
    if is_valid_resource(resource_name) and is_valid_user(user_name) \
    and are_valid_actions([action]):
        for role in users[user_name].roles:
            if resources[resource_name].is_access_authorized(role, action):
                return True
        return False
    else:
        return False
