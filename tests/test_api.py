import asynctest

from mandate import Cognito


class testApi(asynctest.TestCase):
    async def test_register(self):
        cog = Cognito(
            'user_pool_id',  # user pool id
            'client_id',
            user_pool_region='eu-west-2',
            username='test@test.com'
        )

        cog.add_base_attributes(email='test@test.com')

        async with cog.get_client() as client:
            with asynctest.patch.object(client, 'sign_up', new=asynctest.CoroutineMock()):
                await cog.register('test@test.com', 'password')
                client.sign_up.assert_awaited()
