import unittest

from envs import env
from cognito import User,UserObj


class ConitoTestCase(unittest.TestCase):

    def setUp(self):
        self.username = env('COGNITO_TEST_USERNAME')
        self.password = env('COGNITO_TEST_PASSWORD')
        self.user_a = User(username=self.username,
                           password=self.password)
        self.user_a.authenticate()
        self.user_b = User(id_token=self.user_a.id_token,
                           access_token=self.user_a.access_token,
                           refresh_token=self.user_b.refresh_token)

    def test_authenticate(self):
        pass

    def test_authenticate_wrong_password(self):
        pass

    def test_authenticate_wrong_username(self):
        pass

    def test_register(self):
        pass

    def test_renew_tokens(self):
        pass

    def test_update_profile(self):
        pass

    def test_get_user(self):
        pass

    def test_initiate_change_password(self):
        pass

    def test_send_verification(self):
        pass

    def test_validate_verification(self):
        pass

    def test_initiate_forgot_password(self):
        pass

    def test_confirm_forgot_password(self):
        pass

    def test_change_password(self):
        pass

    def test_set_attributes(self):
        pass

