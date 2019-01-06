import unittest
from mandate import Cognito


class testModuleInit(unittest.TestCase):
    def test_object_creation(self):
        cog = Cognito(
            'user_pool_id',  # user pool id
            'client_id',
            user_pool_region='eu-west-2',
            username='test@test.com'
        )

        assert(cog.username == 'test@test.com')
        assert(cog.client_id == 'client_id')
        assert(cog.user_pool_id == 'user_pool_id')
        assert(cog.user_pool_region == 'eu-west-2')

    def test_infer_region(self):
        cog = Cognito(
            'eu-west-1_user_pool_id',  # user pool id
            'client_id',
            username='test@test.com'
        )

        assert(cog.user_pool_id == 'eu-west-1_user_pool_id')
        assert(cog.user_pool_region == 'eu-west-1')
