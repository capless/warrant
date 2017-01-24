import boto3
import ast


class UserObj(object):

    def __init__(self,username, attribute_list):
        self.username = username
        self.pk = username
        for a in attribute_list:
            name = a.get('Name')
            value = a.get('Value')
            if value in ['true','false']:
                value = ast.literal_eval(value.capitalize())
            setattr(self,name,value)


class User(object):

    def __init__(self,user_pool_id,client_id,username,password,access_key=None,secret_key=None,extra_fields=[]):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.username = username
        self.password = password
        self.id_token = None
        self.access_token = None
        self.refresh_token = None
        self.token_type = None
        self.expires_in = None
        if access_key and secret_key:
            self.client = boto3.client('cognito-idp',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                )
        else:
            self.client = boto3.client('cognito-idp')

    def authenticate(self):
        """
        Authenticate the user.
        :param user_pool_id: User Pool Id found in Cognito User Pool
        :param client_id: App Client ID found in the Apps section of the Cognito User Pool
        :return:

        """

        tokens = self.client.admin_initiate_auth(
            UserPoolId=self.user_pool_id,
            ClientId=self.client_id,
            # AuthFlow='USER_SRP_AUTH'|'REFRESH_TOKEN_AUTH'|'REFRESH_TOKEN'|'CUSTOM_AUTH'|'ADMIN_NO_SRP_AUTH',
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': self.username,
                'PASSWORD': self.password
            },
        )
        self.expires_in = tokens['AuthenticationResult']['ExpiresIn']
        self.id_token = tokens['AuthenticationResult']['IdToken']
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.access_token = tokens['AuthenticationResult']['AccessToken']
        self.token_type = tokens['AuthenticationResult']['TokenType']

    def update_profile(self):
        pass

    def get_user(self):
        """
        Get the user's details
        :param user_pool_id: The Cognito User Pool Id
        :return: UserObj object
        """
        return UserObj(self.username,
                       self.client.admin_get_user(
                           UserPoolId=self.user_pool_id,
                           Username=self.username).get('UserAttributes'))

    def initiate_change_password(self):
        pass

    def initiate_forgot_password(self):
        pass

    def confirm_change_password(self):
        pass

    def confirm_forgot_password(self):
        pass

