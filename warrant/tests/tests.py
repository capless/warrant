import unittest

from mock import patch
from envs import env

from warrant import Cognito, UserObj, TokenVerificationException
from warrant.aws_srp import AWSSRP


AWSSRP_TEST_FILE = 'awssrp_test_variables.json'


class UserObjTestCase(unittest.TestCase):

    def setUp(self):
        self.cognito_user_pool_id = env('COGNITO_USER_POOL_ID')
        self.app_id = env('COGNITO_APP_ID')
        self.username = env('COGNITO_TEST_USERNAME')

        self.user = Cognito(self.cognito_user_pool_id, self.app_id,
                            self.username)
        self.user_metadata = {
            'user_status': 'CONFIRMED',
            'username': 'bjones',
        }
        self.user_info = [
            {'Name': 'name', 'Value': 'Brian Jones'},
            {'Name': 'given_name', 'Value': 'Brian'},
            {'Name': 'birthdate', 'Value': '12/7/1980'}
        ]

    def test_init(self):
        u = UserObj('bjones', self.user_info, self.user, self.user_metadata)
        self.assertEqual(u.pk,self.user_metadata.get('username'))
        self.assertEqual(u.name,self.user_info[0].get('Value'))
        self.assertEqual(u.user_status,self.user_metadata.get('user_status'))


class CognitoAuthTestCase(unittest.TestCase):

    def setUp(self):
        self.cognito_user_pool_id = env('COGNITO_USER_POOL_ID')
        self.app_id = env('COGNITO_APP_ID')
        self.username = env('COGNITO_TEST_USERNAME')
        self.password = env('COGNITO_TEST_PASSWORD')
        self.user = Cognito(self.cognito_user_pool_id,self.app_id,
                         username=self.username)


    def test_authenticate(self):
        self.user.authenticate(self.password)
        self.assertNotEqual(self.user.access_token,None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)

    def test_verify_token(self):
        self.user.authenticate(self.password)
        bad_access_token = '{}wrong'.format(self.user.access_token)

        with self.assertRaises(TokenVerificationException) as vm:
            self.user.verify_token(bad_access_token, 'access_token', 'access')

    def test_logout(self):
        self.user.authenticate(self.password)
        self.user.logout()
        self.assertEqual(self.user.id_token,None)
        self.assertEqual(self.user.refresh_token,None)
        self.assertEqual(self.user.access_token,None)

    @patch('warrant.Cognito', autospec=True)
    def test_register(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id,
                         username=self.username)
        res = u.register('sampleuser','sample4#Password',
                given_name='Brian',family_name='Jones',
                name='Brian Jones',
                email='bjones39@capless.io',
                phone_number='+19194894555',gender='Male',
                preferred_username='billyocean')
        #TODO: Write assumptions


    def test_renew_tokens(self):
        self.user.authenticate(self.password)
        self.user.renew_access_token()

    @patch('warrant.Cognito', autospec=True)
    def test_update_profile(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id,
                         username=self.username)
        u.authenticate(self.password)
        u.update_profile({'given_name':'Jenkins'})


    def test_admin_get_user(self):
        u = self.user.admin_get_user()
        self.assertEqual(u.pk,self.username)
    
    def test_check_token(self):
        self.user.authenticate(self.password)
        self.assertFalse(self.user.check_token())


    @patch('warrant.Cognito', autospec=True)
    def test_validate_verification(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id,self.app_id,
                     username=self.username)
        u.validate_verification('4321')

    @patch('warrant.Cognito', autospec=True)
    def test_confirm_forgot_password(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id,
                         username=self.username)
        u.confirm_forgot_password('4553','samplepassword')
        with self.assertRaises(TypeError) as vm:
            u.confirm_forgot_password(self.password)

    @patch('warrant.Cognito', autospec=True)
    def test_change_password(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id,
                         username=self.username)
        u.authenticate(self.password)
        u.change_password(self.password,'crazypassword$45DOG')

        with self.assertRaises(TypeError) as vm:
            self.user.change_password(self.password)

    def test_set_attributes(self):
        u = Cognito(self.cognito_user_pool_id,self.app_id)
        u._set_attributes({
                'ResponseMetadata':{
                    'HTTPStatusCode':200
                }
        },
            {
                'somerandom':'attribute'
            }
        )
        self.assertEquals(u.somerandom,'attribute')

    
    def test_admin_authenticate(self):
        
        self.user.admin_authenticate(self.password)
        self.assertNotEqual(self.user.access_token,None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)


class AWSSRPTestCase(unittest.TestCase):

    def setUp(self):
        self.cognito_user_pool_id = env('COGNITO_USER_POOL_ID')
        self.app_id = env('COGNITO_APP_ID')
        self.username = env('COGNITO_TEST_USERNAME')
        self.password = env('COGNITO_TEST_PASSWORD')

        self.aws = AWSSRP(username=self.username, password=self.password,
                          pool_id=self.cognito_user_pool_id,
                          client_id=self.app_id)

    def tearDown(self):
        del self.aws

    def test_authenticate_user(self):
        tokens = self.aws.authenticate_user()
        self.assertTrue('IdToken' in tokens['AuthenticationResult'])
        self.assertTrue('AccessToken' in tokens['AuthenticationResult'])
        self.assertTrue('RefreshToken' in tokens['AuthenticationResult'])


if __name__ == '__main__':
    unittest.main()
