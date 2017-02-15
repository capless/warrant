from django.contrib.auth import authenticate
from django.test import TestCase, TransactionTestCase, RequestFactory
from django.conf import settings
from botocore.exceptions import ClientError
from middleware import APIKeyMiddleware
from django.contrib.auth.models import AnonymousUser, User

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
