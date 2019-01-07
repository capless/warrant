import asynctest

from mandate import Cognito
from kgb import SpyAgency


class testApi(SpyAgency, asynctest.TestCase):
    async def test_register(self):
        cog = Cognito(
            'user_pool_id',  # user pool id
            'client_id',
            user_pool_region='eu-west-2',
            username='test@test.com'
        )

        cog.add_base_attributes(email='test@test.com')

        async with cog.get_client() as client:
            mock = asynctest.CoroutineMock()
            self.spy_on(client.sign_up, call_fake=mock)
            await cog.register('test@test.com', 'password')
            mock.assert_awaited()
