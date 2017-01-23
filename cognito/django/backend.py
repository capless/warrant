from boto3.exceptions import Boto3Error
from django.conf import settings

from cognito import User


class Pk(object):

    def value_to_string(self,user):
        return str(user.pk)


class Meta(object):

    def __init__(self,user):
        self.pk = Pk()


class CognitoUserPoolAuthBackend(object):

    create_unknown_user = False

    supports_inactive_user = False

    def authenticate(self, username=None, password=None):
        u = User(username,password)
        try:
            u.authenticate(settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID)
        except Boto3Error:
            return None
        return u.get_user()

    def get_user(self, user_id):
        user_cls = self.get_user_class()
        u = User(user_id,'None')
        user = u.get_user(settings.COGNITO_USER_POOL_ID)
        if not user:
            raise KeyError
        return user

    def get_user_class(self):
        return User