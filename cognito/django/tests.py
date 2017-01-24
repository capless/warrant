from django.contrib.auth import authenticate
from django.test import TransactionTestCase
from django.conf import settings


class AuthTests(TransactionTestCase):

    def test_user_authentication(self):
        user = authenticate(username=settings.COGNITO_TEST_USERNAME,
                            password=settings.COGNITO_TEST_PASSWORD)
        self.assertIsNotNone(user)