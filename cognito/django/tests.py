from django.contrib.auth import authenticate
from django.test import TransactionTestCase
from django.conf import settings
from botocore.exceptions import ClientError

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
