from envs import env
from flask_security.datastore import UserDatastore

from warrant import Cognito


class CognitoDatastore(object):

    def __init__(self):
        self.user_class = Cognito(env('COGNITO_USER_POOL_ID'),env('COGNITO_CLIENT_ID'))

    def commit(self):
        pass

    def put(self, model):
        model.save()

    def delete(self, model):
        model.delete()


class CognitoUserDatastore(CognitoDatastore, UserDatastore):

    def __init__(self, db, user_model, role_model, role_link):
        CognitoDatastore.__init__(self, db)
        UserDatastore.__init__(self, user_model, role_model)
        self.UserRole = role_link

    def get_user(self, identifier):
        self.user_class.username = identifier
        return self.user_class.admin_get_user()

    def find_user(self, **kwargs):
        try:
            return self.user_model.filter(**kwargs).get()
        except self.user_model.DoesNotExist:
            return None

    def find_role(self, role):
        try:
            return self.role_model.filter(name=role).get()
        except self.role_model.DoesNotExist:
            return None

    def create_user(self, **kwargs):
        """Creates and returns a new user from the given parameters."""
        roles = kwargs.pop('roles', [])
        user = self.user_model(**self._prepare_create_user_args(**kwargs))
        user = self.put(user)
        for role in roles:
            self.add_role_to_user(user, role)
        self.put(user)
        return user

    def add_role_to_user(self, user, role):
        """Adds a role to a user.
        :param user: The user to manipulate
        :param role: The role to add to the user
        """
        user, role = self._prepare_role_modify_args(user, role)
        result = self.UserRole.select() \
            .where(self.UserRole.user == user.id, self.UserRole.role == role.id)
        if result.count():
            return False
        else:
            self.put(self.UserRole.create(user=user.id, role=role.id))
            return True

    def remove_role_from_user(self, user, role):
        """Removes a role from a user.


