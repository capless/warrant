import unittest
import datetime

from mock import patch
from envs import env
from placebo.utils import placebo_session
from botocore.exceptions import ClientError

from cognito import Cognito,UserObj,attribute_dict


class UserObjTestCase(unittest.TestCase):

    def setUp(self):
        self.user_metadata = {
            'user_status': 'CONFIRMED',
            'username': 'bjones',
            'expires_in': '5',
            'expires_datetime': datetime.datetime.now() + datetime.timedelta(seconds=5)
        }
        self.user_info = [
            {'Name': 'name', 'Value': 'Brian Jones'},
            {'Name': 'given_name', 'Value': 'Brian'},
            {'Name': 'birthdate', 'Value': '12/7/1980'}
        ]

    def test_init(self):
        u = UserObj('bjones', self.user_info, self.user_metadata)
        self.assertEqual(u.pk,self.user_metadata.get('username'))
        self.assertEqual(u.name,self.user_info[0].get('Value'))
        self.assertEqual(u.user_status,self.user_metadata.get('user_status'))


class AttributeDictTestCase(unittest.TestCase):

    def test_func(self):
        ad = attribute_dict({'username':'bjones','email':'bjones@example.com'})
        self.assertEqual([
            {'Name':'username','Value':'bjones'},
            {'Name':'email','Value':'bjones@example.com'}
        ],ad)


class CognitoTestCase(unittest.TestCase):

    def setUp(self):
        self.cognito_user_pool_id = env('COGNITO_USER_POOL_ID')
        self.app_id = env('COGNITO_APP_ID')
        self.username = env('COGNITO_TEST_USERNAME')
        self.password = env('COGNITO_TEST_PASSWORD')
        self.user = Cognito(self.cognito_user_pool_id,self.app_id,
                         self.username,self.password)

    @placebo_session
    def test_authenticate(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        self.assertNotEqual(self.user.access_token,None)
        self.assertNotEqual(self.user.id_token, None)
        self.assertNotEqual(self.user.refresh_token, None)

    @placebo_session
    def test_logout(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        self.user.logout()
        self.assertEqual(self.user.id_token,None)
        self.assertEqual(self.user.refresh_token,None)
        self.assertEqual(self.user.access_token,None)

    @placebo_session
    def test_register(self,session):
        self.user.switch_session(session)
        res = self.user.register('sampleuser','sample4#Password',
                given_name='Brian',family_name='Jones',
                name='Brian Jones',
                email='bjones39@capless.io',
                phone_number='+19194894555',gender='Male',
                preferred_username='billyocean')
        #TODO: Write assumptions


    @placebo_session
    def test_renew_tokens(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        acc_token = self.user.access_token
        self.user.renew_access_token()
        acc_token_b = self.user.access_token
        self.assertNotEqual(acc_token,acc_token_b)

    @placebo_session
    def test_update_profile(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        self.user.update_profile({'given_name':'Jenkins'})
        u = self.user.get_user()
        self.assertEquals(u.given_name,'Jenkins')

    @placebo_session
    def test_get_user(self,session):
        self.user.switch_session(session)
        u = self.user.get_user()
        self.assertEqual(u.pk,self.username)

    @placebo_session
    def test_send_verification(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        self.user.send_verification()
        with self.assertRaises(ClientError) as vm:
            self.user.send_verification(attribute='randomattribute')

    @placebo_session
    def test_check_token(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        self.user.expires_datetime = datetime.datetime.now() - datetime.timedelta(days=1)
        og_exp_time = self.user.expires_datetime
        og_acc_token = self.user.access_token
        self.user.check_token()
        self.assertNotEqual(og_exp_time,self.user.expires_datetime)
        self.assertNotEquals(og_acc_token,self.user.access_token)


    @patch('cognito.Cognito', autospec=True)
    def test_validate_verification(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id,self.app_id,
                     username=self.username,password=self.password)
        u.validate_verification('4321')

    @patch('cognito.Cognito', autospec=True)
    def test_confirm_forgot_password(self,cognito_user):
        u = cognito_user(self.cognito_user_pool_id, self.app_id,
                         username=self.username, password=self.password)
        u.confirm_forgot_password('4553','samplepassword')
        with self.assertRaises(TypeError) as vm:
            u.confirm_forgot_password(self.password)

    @placebo_session
    def test_change_password(self,session):
        self.user.switch_session(session)
        self.user.authenticate()
        og_password = self.user.password
        self.user.change_password(self.password,'crazypassword$45DOG')
        self.assertNotEqual(self.user.password,og_password)
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

