import abc

from boto3.exceptions import Boto3Error
import django
from django.conf import settings

from cognito import User


class Pk(object):

    def value_to_string(self,user):
        return str(user.pk)


class Meta(object):

    def __init__(self,user):
        self.pk = Pk()


class AbstractCognitoUserPoolAuthBackend(object):
    __metaclass__ = abc.ABCMeta

    create_unknown_user = False

    supports_inactive_user = False

    @abc.abstractmethod
    def authenticate(self):
        """
        Authenticate a cognito User.
        """
        pass

    def get_user(self, request, user_id):

        user_cls = self.get_user_class()
        u = User(
            settings.COGNITO_USER_POOL_ID, settings.COGNITO_APP_ID,
            username=user_id)
        user = u.get_user()
        if not user:
            raise KeyError
        return user

    def get_user_class(self):
        return User


if django.VERSION[1] > 10:
    class CognitoUserPoolAuthBackend(AbstractCognitoUserPoolAuthBackend):
        def authenticate(cls, request, username=None, password=None):
            """
            Authenticate a cognito User and store an access, ID and 
            refresh token in the session.
            """
            u = User(
                settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,
                username=username, password=password)
            try:
                u.authenticate()
            except Boto3Error:
                return None
            request.session['ACCESS_TOKEN'] = u.access_token
            request.session['ID_TOKEN'] = u.id_token
            request.session['REFRESH_TOKEN'] = u.refresh_token
            request.session.save()
            return u.get_user()
else:
    class CognitoUserPoolAuthBackend(AbstractCognitoUserPoolAuthBackend):
        def authenticate(cls, username=None, password=None):
            """
            Authenticate a cognito User.
            """
            u = User(
                settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,
                username=username, password=password)
            try:
                u.authenticate()
            except Boto3Error:
                return None
            return u.get_user()
