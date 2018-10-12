class Resource:
    def __init__(self, resource_name, permissions = {}):
        self.name = resource_name
        self.permissions = permissions

    def add_permission(self, role, actions):
        try:
            self.permissions[role.name] = set(self.permissions[role.name] + actions)
        except KeyError:
            self.permissions[role.name] = actions

    def is_access_authorized(self, role, action):
        try:
            for authorized_action in self.permissions[role.name]:
                if action == authorized_action:
                    return True
        except KeyError:
            return False
        return False
