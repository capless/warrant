import unittest
from mandate.utils import cognito_to_dict, dict_to_cognito


class TestUtils(unittest.TestCase):
    def test_cognito_to_dict(self):
        self.assertEqual(
            cognito_to_dict(
                [
                    {
                        'Name': 'a',
                        'Value': 'test'
                    },
                    {
                        'Name': 'test',
                        'Value': 'test2'
                    },
                    {
                        'Name': 'bool1',
                        'Value': 'true',
                    },
                    {
                        'Name': 'bool2',
                        'Value': 'false',
                    },
                    {
                        'Name': 'user_name',
                        'Value': 'kelly'
                    }
                ],
                {
                    'user_name': 'username'
                }
            ),
            {
                'a': 'test',
                'test': 'test2',
                'bool1': True,
                'bool2': False,
                'username': 'kelly'
            }
        )

    def test_dict_to_cognito(self):
        self.assertEqual(
            dict_to_cognito({
                'a': 'b',
                'c': 'd'
            }),
            [{
                'Name': 'a',
                'Value': 'b'
            }, {
                'Name': 'c',
                'Value': 'd'
            }]
        )
