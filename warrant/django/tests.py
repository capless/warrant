from mock import patch, MagicMock
from botocore.exceptions import ClientError
from middleware import APIKeyMiddleware

from django.contrib.auth.models import AnonymousUser, User
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, signals
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TestCase, TransactionTestCase
from django.test.client import RequestFactory
from django.utils.six import iteritems

from warrant.django.models import ApiKey
from warrant.django.backend import CognitoBackend
from warrant import Cognito as CognitoUser


class AuthTests(TransactionTestCase):
    def set_tokens(self, mock_cognito_user):
        mock_cognito_user.access_token = 'accesstoken'
        mock_cognito_user.id_token = 'idtoken'
        mock_cognito_user.refresh_token = 'refreshtoken'

    def create_mock_user_obj(self, **kwargs):
        """
        Create a mock UserObj
        :param: kwargs containing desired attrs
        :return: returns mock UserObj
        """
        mock_user_obj = MagicMock(
            user_status=kwargs.pop('user_status', 'CONFIRMED'),
            username=kwargs.pop('access_token', 'testuser'),
            email=kwargs.pop('email', 'test@email.com'),
            given_name=kwargs.pop('given_name', 'FirstName'),
            family_name=kwargs.pop('family_name', 'LastName'),
        )
        for k, v in kwargs.iteritems():
            setattr(mock_user_obj, k, v)

        return mock_user_obj

    def setup_mock_user(self, mock_cognito_user):
        """
        Configure mocked Cognito User
        :param mock_cognito_user: mock Cognito User
        """
        mock_cognito_user.return_value = mock_cognito_user
        self.set_tokens(mock_cognito_user)

        mock_user_obj = self.create_mock_user_obj()
        mock_cognito_user.get_user.return_value = mock_user_obj

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_user_authentication(self, mock_cognito_user):
        self.setup_mock_user(mock_cognito_user)

        user = authenticate(username='testuser',
                            password='password')
        self.assertIsNotNone(user)

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_user_authentication_wrong_password(self, mock_cognito_user):
        mock_cognito_user.return_value = mock_cognito_user
        mock_cognito_user.authenticate.side_effect = ClientError(
            {
                'Error': 
                    {
                        'Message': 'Incorrect username or password.', 'Code': 'NotAuthorizedException'
                    }
            },
            'AdminInitiateAuth')
        user = authenticate(username='username',
                            password='wrongpassword')

        self.assertIsNone(user)

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_user_authentication_wrong_username(self, mock_cognito_user):
        mock_cognito_user.return_value = mock_cognito_user
        mock_cognito_user.authenticate.side_effect = ClientError(
            {
                'Error': 
                    {
                        'Message': 'Incorrect username or password.', 'Code': 'NotAuthorizedException'
                    }
            },
            'AdminInitiateAuth')
        user = authenticate(username='wrongusername',
                            password='password')

        self.assertIsNone(user)

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_client_login(self, mock_cognito_user):
        self.setup_mock_user(mock_cognito_user)

        user = self.client.login(username='testuser',
                                 password='password')
        self.assertTrue(user)

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_boto_error_raised(self, mock_cognito_user):
        """
        Check that any error other than NotAuthorizedException is
        raised as an exception
        """
        mock_cognito_user.return_value = mock_cognito_user
        mock_cognito_user.authenticate.side_effect = ClientError(
            {
                'Error': 
                    {
                        'Message': 'Generic Error Message.', 'Code': 'SomeError'
                    }
            },
            'AdminInitiateAuth')
        with self.assertRaises(ClientError) as error:
            user = authenticate(username='testuser',
                                password='password')
        self.assertEqual(error.exception.response['Error']['Code'], 'SomeError')

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_new_user_created(self, mock_cognito_user):
        self.setup_mock_user(mock_cognito_user)

        User = get_user_model()
        self.assertEqual(User.objects.count(), 0) 

        user = authenticate(username='testuser',
                            password='password')

        self.assertEqual(User.objects.count(), 1) 
        self.assertEqual(user.username, 'testuser')

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_existing_user_updated(self, mock_cognito_user):
        self.setup_mock_user(mock_cognito_user)

        User = get_user_model()
        existing_user = User.objects.create(username='testuser', email='None')
        user = authenticate(username='testuser',
                            password='password')
        self.assertEqual(user.id, existing_user.id)
        self.assertNotEqual(user.email, existing_user.email)
        self.assertEqual(User.objects.count(), 1)

        updated_user = User.objects.get(username='testuser')
        self.assertEqual(updated_user.email, user.email)
        self.assertEqual(updated_user.id, user.id)

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_existing_user_updated_disabled_create_unknown_user(self, mock_cognito_user):
        class AlternateCognitoBackend(CognitoBackend):
            create_unknown_user = False

        self.setup_mock_user(mock_cognito_user)

        User = get_user_model()
        existing_user = User.objects.create(username='testuser', email='None')

        backend = AlternateCognitoBackend()
        user = backend.authenticate(username='testuser',
                            password='password')
        self.assertEqual(user.id, existing_user.id)
        self.assertNotEqual(user.email, existing_user)
        self.assertEqual(User.objects.count(), 1)

        updated_user = User.objects.get(username='testuser')
        self.assertEqual(updated_user.email, user.email)
        self.assertEqual(updated_user.id, user.id)

    @patch('cognito.django.backend.CognitoUser', autospec=True)
    def test_user_not_found_disabled_create_unknown_user(self, mock_cognito_user):
        class AlternateCognitoBackend(CognitoBackend):
            create_unknown_user = False

        self.setup_mock_user(mock_cognito_user)

        backend = AlternateCognitoBackend()
        user = backend.authenticate(username='testuser',
                            password='password')

        self.assertIsNone(user)

    @patch('cognito.django.backend.CognitoUser')
    def test_inactive_user(self, mock_cognito_user):
        """
        Check that inactive users cannot login.
        In our case, a user is considered inactive if their
        user status in Cognito is 'ARCHIVED' or 'COMPROMISED' or 'UNKNOWN'
        """
        mock_cognito_user.return_value = mock_cognito_user
        mock_user_obj = MagicMock()
        mock_user_obj.user_status = 'COMPROMISED'
        mock_cognito_user.get_user.return_value = mock_user_obj
        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)
        self.assertIsNone(user)

        mock_user_obj.user_status = 'ARCHIVED'
        mock_cognito_user.get_user.return_value = mock_user_obj
        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)
        self.assertIsNone(user)

        mock_user_obj.user_status = 'UNKNOWN'
        mock_cognito_user.get_user.return_value = mock_user_obj
        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)
        self.assertIsNone(user)

    def test_add_user_tokens(self):
        User = get_user_model()
        user = User.objects.create(username=settings.COGNITO_TEST_USERNAME)
        user.access_token = 'access_token_value'
        user.id_token = 'id_token_value'
        user.refresh_token = 'refresh_token_value'
        user.backend = 'cognito.django.backend.CognitoBackend'

        request = RequestFactory().get('/login')
        middleware = SessionMiddleware()
        middleware.process_request(request)
        request.session.save()
        signals.user_logged_in.send(sender=user.__class__, request=request, user=user)

        self.assertEqual(request.session['ACCESS_TOKEN'], 'access_token_value')
        self.assertEqual(request.session['ID_TOKEN'], 'id_token_value')
        self.assertEqual(request.session['REFRESH_TOKEN'], 'refresh_token_value')

    def test_model_backend(self):
        """
        Check that the logged in signal plays nice with other backends
        """
        User = get_user_model()
        user = User.objects.create(username=settings.COGNITO_TEST_USERNAME)
        user.backend = 'django.contrib.auth.backends.ModelBackend'

        request = RequestFactory().get('/login')
        middleware = SessionMiddleware()
        middleware.process_request(request)
        request.session.save()
        signals.user_logged_in.send(sender=user.__class__, request=request, user=user)

        self.assertEquals(str(em.exception), 'An error occurred (UserNotFoundException) '\
                                             'when calling the AdminInitiateAuth '\
                                             'operation: User does not exist.')

class MiddleWareTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_header_missing(self):
        request = self.factory.get('/does/not/matter')

        request.user = AnonymousUser()

        APIKeyMiddleware.process_request(request)

        # Test that missing headers responds properly
        self.assertFalse(hasattr(request, 'api_key'))

    def test_header_transfers(self):
        request = self.factory.get('/does/not/matter', HTTP_AUTHORIZATION_ID='testapikey')

        request.user = AnonymousUser()

        APIKeyMiddleware.process_request(request)

        # Now test with proper headers in place
        self.assertEqual(request.api_key, 'testapikey')


class ApiKeyModelTestCase(TransactionTestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='testuser')

    def test_get_existing_active_key(self):
        # if we have an existing, active ApiKey for a user
        active_key = ApiKey.objects.create(user_id=self.user.id, apikey='abcde', active=True)
        inactive_key = ApiKey.objects.create(user_id=self.user.id, apikey='xyz', active=False)
        # then when we call get_or_create_apikey
        fetched_key, created = ApiKey.objects.get_or_create_apikey(self.user.id, active_key.apikey)
        # we get back the same key
        self.assertEqual(active_key.id, fetched_key.id)
        self.assertFalse(created)

    def test_get_existing_inactive_key(self):
        # if we have an existing, inactive ApiKey for a user
        inactive_key = ApiKey.objects.create(user_id=self.user.id, apikey='abcde', active=False)
        active_key = ApiKey.objects.create(user_id=self.user.id, apikey='xyz', active=True)
        # then when we call get_or_create_apikey with return_inactive=True
        fetched_key, created = ApiKey.objects.get_or_create_apikey(self.user.id, inactive_key.apikey, return_inactive=True)
        # we get back the same key
        self.assertEqual(inactive_key.id, fetched_key.id)
        self.assertFalse(created)

    def test_new_key_created_existing_inactive(self):
        # if there are existing apikeys but none of them are active
        inactive_key = ApiKey.objects.create(user_id=self.user.id, apikey='cdef')
        # when we call get_or_create_apikey
        fetched_key, created = ApiKey.objects.get_or_create_apikey(self.user.id, 'abcde', return_inactive=True)
        # a new key is created
        self.assertNotEqual(inactive_key.id, fetched_key.id)
        self.assertEqual(fetched_key.apikey, 'abcde')
        self.assertTrue(created)

    def test_new_key_created_no_existing(self):
        # if there are no existing apikeys for a user
        # then when we call get_or_create_apikey
        fetched_key, created = ApiKey.objects.get_or_create_apikey(self.user.id, 'abcde', return_inactive=True)
        # we get a new key
        self.assertEqual(fetched_key.apikey, 'abcde')
        self.assertEqual(fetched_key.user_id, self.user.id)
        self.assertTrue(fetched_key.active)
        self.assertTrue(created)

    def test_replace_existing_active_key(self):
        # if there is an existing, active key
        ApiKey.objects.create(user_id=self.user.id, apikey='abcde', active=True)
        # if we pass a new apikey to get_or_create_apikey
        fetched_key, created = ApiKey.objects.get_or_create_apikey(self.user.id, 'fghi')
        # then the previous, active key is deactivated
        old_key = ApiKey.objects.get(apikey='abcde')
        self.assertFalse(old_key.active)
        # and a new one has been created
        self.assertNotEqual(old_key.id, fetched_key.id)
        self.assertEqual(fetched_key.apikey, 'fghi')
        self.assertTrue(fetched_key.active)
        self.assertTrue(created)
