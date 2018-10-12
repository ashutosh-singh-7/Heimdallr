import unittest

import Heimdallr


class AlohomoraTests(unittest.TestCase):
    def tearDown(self):
        Heimdallr.roles = {}
        Heimdallr.users = {}
        Heimdallr.resources = {}

    def add_role(self, role_name, length_check):
        self.assertTrue(Heimdallr.add_role(role_name))
        self.assertEqual(len(Heimdallr.get_roles()), length_check)
        self.assertEqual(Heimdallr.get_roles()[role_name].name, role_name)

    def add_user(self, user_name, role_names, length_check):
        self.assertTrue(Heimdallr.add_user(user_name, role_names))
        self.assertEqual(len(Heimdallr.get_users()), length_check)
        self.assertEqual(Heimdallr.get_users()[user_name].name, user_name)
        self.assertItemsEqual(Heimdallr.get_users()[user_name].roles, [Heimdallr.roles[role_name] for role_name in role_names])

    def add_resource(self, resource_name, role_name, actions, length_check):
        self.assertTrue(Heimdallr.add_resource(resource_name, role_name, actions))
        self.assertEqual(len(Heimdallr.get_resources()), length_check)
        self.assertEqual(Heimdallr.get_resources()[resource_name].name, resource_name)
        self.assertItemsEqual(Heimdallr.get_resources()[resource_name].permissions[role_name], actions)

    def test_add_role(self):
        self.add_role('role', 1)

    def test_check_duplicate_role(self):
        self.assertTrue(Heimdallr.add_role('role'))
        self.assertFalse(Heimdallr.add_role('role'))
        self.assertEqual(len(Heimdallr.get_roles()), 1)

    def test_add_multiple_roles(self):
        self.add_role('role_1', 1)
        self.add_role('role_2', 2)

    def test_add_user(self):
        self.add_role('role', 1)
        self.add_user('user', ['role'], 1)

    def test_add_user_with_multiple_roles(self):
        self.add_role('role_1', 1)
        self.add_role('role_2', 2)

        self.add_user('user', ['role_1', 'role_2'], 1)

    def test_add_multiple_users(self):
        self.add_role('role_1', 1)
        self.add_role('role_2', 2)

        self.add_user('user_1', ['role_1'], 1)
        self.add_user('user_2', ['role_2', 'role_1'], 2)

    def test_add_duplicate_user(self):
        self.add_role('role', 1)
        self.add_user('user', ['role'], 1)

        self.assertFalse(Heimdallr.add_user('user', ['role']))
        self.assertEqual(len(Heimdallr.get_users()), 1)

    def test_add_user_with_unexisting_role(self):
        self.assertFalse(Heimdallr.add_user('user', ['role']))

    def test_add_role_to_user(self):
        self.add_role('role_1', 1)
        self.add_user('user', ['role_1'], 1)

        self.add_role('role_2', 2)
        self.assertTrue(Heimdallr.add_role_to_user('user', 'role_2'))
        self.assertItemsEqual(Heimdallr.users['user'].roles, [Heimdallr.roles[role_name] for role_name in ['role_1', 'role_2']])

    def test_add_resource(self):
        self.add_role('role', 1)
        self.add_resource('resource', 'role', ['READ'], 1)

    def test_add_multiple_resources(self):
        self.add_role('role_1', 1)
        self.add_role('role_2', 2)

        self.add_resource('resource_1', 'role_2', ['READ', 'WRITE', 'DELETE'], 1)
        self.add_resource('resource_2', 'role_1', ['READ', 'DELETE'], 2)

    def test_add_duplicate_resource(self):
        self.add_role('role_1', 1)
        self.add_resource('resource', 'role_1', ['READ', 'WRITE', 'DELETE'], 1)
        self.assertFalse(Heimdallr.add_resource('resource', 'role_1', ['READ', 'WRITE', 'DELETE']))
        self.assertEqual(len(Heimdallr.get_resources()), 1)

    def test_add_resource_with_unexisting_role(self):
        self.assertFalse(Heimdallr.add_resource('resource', 'role_1', ['READ', 'WRITE', 'DELETE']))

    def test_add_resource_with_unexisting_action(self):
        self.add_role('role_1', 1)
        self.assertFalse(Heimdallr.add_resource('resource', 'role_1', ['EVAPORATE']))

    def test_authorized_access(self):
        self.add_role('role', 1)
        self.add_user('user', ['role'], 1)
        self.add_resource('resource', 'role', ['READ', 'WRITE', 'DELETE'], 1)

        self.assertTrue(Heimdallr.is_action_authorized('resource', 'user', 'READ'))

    def test_unauthorized_access(self):
        self.add_role('role', 1)
        self.add_user('user', ['role'], 1)
        self.add_resource('resource', 'role', ['READ', 'WRITE'], 1)

        self.assertFalse(Heimdallr.is_action_authorized('resource', 'user', 'DELETE'))
        self.assertFalse(Heimdallr.is_action_authorized('resource', 'user', 'EVAPORATE'))
        self.assertFalse(Heimdallr.is_action_authorized('resource', 'wrong_user', 'READ'))
        self.assertFalse(Heimdallr.is_action_authorized('wrong_resource', 'user', 'READ'))

    def test_add_action_to_role(self):
        self.add_role('role', 1)
        self.add_user('user', ['role'], 1)
        self.add_resource('resource', 'role', ['READ', 'WRITE'], 1)

        self.assertFalse(Heimdallr.is_action_authorized('resource', 'user', 'DELETE'))

        self.assertTrue(Heimdallr.add_access_to_resource('resource', 'role', ['DELETE']))
        self.assertTrue(Heimdallr.is_action_authorized('resource', 'user', 'DELETE'))

    def test_add_role_to_user(self):
        self.add_role('role_1', 1)
        self.add_user('user', ['role_1'], 1)
        self.add_resource('resource', 'role_1', ['READ', 'WRITE'], 1)

        self.assertFalse(Heimdallr.is_action_authorized('resource', 'user', 'DELETE'))

        self.add_role('role_2', 2)
        self.assertTrue(Heimdallr.add_access_to_resource('resource', 'role_2', ['DELETE']))
        self.assertTrue(Heimdallr.add_role_to_user('user', 'role_2'))
        self.assertTrue(Heimdallr.is_action_authorized('resource', 'user', 'DELETE'))


if __name__ == '__main__':
    unittest.main()
