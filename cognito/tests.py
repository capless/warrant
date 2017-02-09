import unittest

from envs import env
from cognito import User,UserObj


class ConitoTestCase(unittest.TestCase):

    def setUp(self):
        username = env('COGNITO_TEST_USERNAME')
        password = env('COGNITO_TEST_PASSWORD')
        self.user_a = User(username=username,password=password)
        self.user_a.authenticate()
        self.user_b = User(id_token=self.user_a.id_token)

    def test_authenticate(self):
        pass

