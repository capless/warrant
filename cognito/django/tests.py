from mock import patch, MagicMock

from botocore.exceptions import ClientError

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, signals
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import TransactionTestCase
from django.test.client import RequestFactory

from cognito.django.backend import CognitoUserPoolAuthBackend

class AuthTests(TransactionTestCase):

    def test_user_authentication(self):
        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)

        self.assertIsNotNone(user)

    def test_user_authentication_wrong_password(self):
        with self.assertRaises(ClientError) as em:

            user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD+'wrong')

        self.assertEquals(str(em.exception),'An error occurred (NotAuthorizedException) '\
                                  'when calling the AdminInitiateAuth '\
                                  'operation: Incorrect username or password.')

    def test_user_authentication_wrong_username(self):
        with self.assertRaises(ClientError) as em:
            user = authenticate(username=settings.COGNITO_TEST_USERNAME + 'wrong',
                                password=settings.COGNITO_TEST_PASSWORD )

        self.assertEquals(str(em.exception), 'An error occurred (UserNotFoundException) '\
                                             'when calling the AdminInitiateAuth '\
                                             'operation: User does not exist.')

    def test_client_login(self):
        user = self.client.login(username=settings.COGNITO_TEST_USERNAME,
                                 password=settings.COGNITO_TEST_PASSWORD)
        self.assertIsNotNone(user)

    def test_new_user_created(self):
        User = get_user_model()
        self.assertEqual(User.objects.count(), 0) 

        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)

        self.assertEqual(User.objects.count(), 1) 
        self.assertEqual(user.username, settings.COGNITO_TEST_USERNAME)

    def test_existing_user_updated(self):
        User = get_user_model()
        existing_user = User.objects.create(username=settings.COGNITO_TEST_USERNAME, email='None')
        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)
        self.assertEqual(user.id, existing_user.id)
        self.assertNotEqual(user.email, existing_user)
        self.assertEqual(User.objects.count(), 1)

        updated_user = User.objects.get(username=settings.COGNITO_TEST_USERNAME)
        self.assertEqual(updated_user.email, user.email)
        self.assertEqual(updated_user.id, user.id)

    def test_existing_user_updated_disabled_create_unknown_user(self):
        class AlternateCognitoUserPoolAuthBackend(CognitoUserPoolAuthBackend):
            create_unknown_user = False

        User = get_user_model()
        existing_user = User.objects.create(username=settings.COGNITO_TEST_USERNAME, email='None')

        backend = AlternateCognitoUserPoolAuthBackend()
        user = backend.authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)
        self.assertEqual(user.id, existing_user.id)
        self.assertNotEqual(user.email, existing_user)
        self.assertEqual(User.objects.count(), 1)

        updated_user = User.objects.get(username=settings.COGNITO_TEST_USERNAME)
        self.assertEqual(updated_user.email, user.email)
        self.assertEqual(updated_user.id, user.id)

    def test_user_not_found_disabled_create_unknown_user(self):
        class AlternateCognitoUserPoolAuthBackend(CognitoUserPoolAuthBackend):
            create_unknown_user = False

        backend = AlternateCognitoUserPoolAuthBackend()
        user = backend.authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)

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
        setattr(user, 'access_token', 'access_token_value')
        setattr(user, 'id_token', 'id_token_value')
        setattr(user, 'refresh_token', 'refresh_token_value')

        request = RequestFactory().get('/login')
        middleware = SessionMiddleware()
        middleware.process_request(request)
        request.session.save()
        signals.user_logged_in.send(sender=user.__class__, request=request, user=user)

        self.assertEqual(request.session['ACCESS_TOKEN'], 'access_token_value')
        self.assertEqual(request.session['ID_TOKEN'], 'id_token_value')
        self.assertEqual(request.session['REFRESH_TOKEN'], 'refresh_token_value')
