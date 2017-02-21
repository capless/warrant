"""Custom Django authentication backend"""
import abc

from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError
from django import VERSION as DJANGO_VERSION
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.utils.six import iteritems

from cognito import Cognito as CognitoUser


class Pk(object):

    def value_to_string(self,user):
        return str(user.pk)


class Meta(object):

    def __init__(self,user):
        self.pk = Pk()


class AbstractCognitoBackend(ModelBackend):
    __metaclass__ = abc.ABCMeta

    create_unknown_user = True

    supports_inactive_user = False

    INACTIVE_USER_STATUS = ['ARCHIVED', 'COMPROMISED', 'UNKNOWN']

    UNAUTHORIZED_ERROR_CODE = 'NotAuthorizedException'

    USER_NOT_FOUND_ERROR_CODE = 'UserNotFoundException'

    # Mapping of Cognito User attribute name to Django User attribute name
    COGNITO_ATTR_MAPPING = getattr(settings, 'COGNITO_ATTR_MAPPING',
        {
            'email': 'email',
            'given_name': 'first_name',
            'family_name': 'last_name',
        }
    )

    @abc.abstractmethod
    def authenticate(self, username=None, password=None):
        """
        Authenticate a Cognito User
        :param username: Cognito username
        :param password: Cognito password
        :return: returns User instance of AUTH_USER_MODEL or None
        """
        cognito_user = CognitoUser(
            settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,
            username=username, password=password)
        try:
            cognito_user.authenticate()
        except (Boto3Error, ClientError) as e:
            return self.handle_error_response(e)
        user_obj = cognito_user.get_user()
        if not self.cognito_user_can_authenticate(user_obj):
            return None

        return self._update_or_create_user(user_obj, cognito_user)

    def handle_error_response(self, error):
        error_code = error.response['Error']['Code']
        if error_code in [
                AbstractCognitoBackend.UNAUTHORIZED_ERROR_CODE,
                AbstractCognitoBackend.USER_NOT_FOUND_ERROR_CODE
            ]:
            return None
        raise error

    def cognito_user_can_authenticate(self, user_obj):
        """
        Reject users if their Cognito user status is listed in
        INACTIVE_USER_STATUS
        :param user_obj: cognito.UserObj object
        :return: Boolean
        """
        if not self.supports_inactive_user and \
               user_obj.user_status in AbstractCognitoBackend.INACTIVE_USER_STATUS:
            return False
        return True

    def _update_or_create_user(self, user_obj, cognito_user):
        """
        Update existing user or create a new Django user.
        :param user_obj: cognito.UserObj object
        :param cognito_user: cognito.User object 
        :return: User instance of AUTH_USER_MODEL, with token attrs attached
        """
        user_attrs = {}
        for cognito_attr, django_attr in iteritems(AbstractCognitoBackend.COGNITO_ATTR_MAPPING):
            user_attrs[django_attr] = getattr(user_obj, cognito_attr)

        UserModel = get_user_model()
        if self.create_unknown_user:
            user, created = UserModel.objects.update_or_create(
                username=user_obj.username,
                defaults=user_attrs)
        else:
            try:
                user = UserModel.objects.get(username=user_obj.username)
                for k, v in iteritems(user_attrs):
                    setattr(user, k, v)
                user.save()
            except UserModel.DoesNotExist:
                user = None
        # Attach tokens to user object
        if user:
            setattr(user, 'access_token', cognito_user.access_token)
            setattr(user, 'id_token', cognito_user.id_token)
            setattr(user, 'refresh_token', cognito_user.refresh_token)
        return user            


if DJANGO_VERSION[1] > 10:
    class CognitoBackend(AbstractCognitoBackend):
        def authenticate(self, request, username=None, password=None):
            """
            Authenticate a Cognito User and store an access, ID and 
            refresh token in the session.
            """
            user = super(CognitoBackend, self).authenticate(
                username=username, password=password)
            if user:
                request.session['ACCESS_TOKEN'] = user.access_token
                request.session['ID_TOKEN'] = user.id_token
                request.session['REFRESH_TOKEN'] = user.refresh_token
                request.session.save()
            return user
else:
    class CognitoBackend(AbstractCognitoBackend):
        def authenticate(self, username=None, password=None):
            """
            Authenticate a Cognito User
            """
            return super(CognitoBackend, self).authenticate(
                username=username, password=password)
