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

    def authenticate(self,request, username=None, password=None):
        u = User(settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,username,password)
        try:
            u.authenticate()
        except Boto3Error:
            return None
        request.session['ACCESS_TOKEN'] = u.access_token
        request.session['ID_TOKEN'] = u.id_token
        request.session['REFRESH_TOKEN'] = u.refresh_token
        request.session.save()
        return u.get_user()

    def get_user(self, request, user_id):

        user_cls = self.get_user_class()
        u = User(user_id,'None',user_pool_id=settings.COGNITO_USER_POOL_ID,app_id=settings.COGNITO_APP_ID,)
        user = u.get_user()
        if not user:
            raise KeyError
        return user

    def get_user_class(self):
        return User