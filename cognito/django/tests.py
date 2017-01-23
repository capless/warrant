from django.contrib.auth import authenticate
from django.test import TransactionTestCase

class AuthTests(TransactionTestCase):

    def test_user_authentication(self):
        authdata = {
            'username': 'mickey',
            'password': 'secret',
            'email': 'user@host.com',
        }
        data = authdata.copy()
        data.update({
            'email': 'mickey@mice.com',
        })
        user = User(**data)
        user.set_password(data.get('password'))
        user.save()

        user = authenticate(username=authdata.get('username'), password=authdata.get('password'))
        self.assertIsNotNone(user)