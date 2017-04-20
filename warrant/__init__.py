import ast
import boto3
import datetime
import requests

from envs import env
from jose import jwk, jwt
from jose.utils import base64url_decode
from .aws_srp import AWSSRP


def cognito_to_dict(attr_list,attr_map=dict()):
    attr_dict = dict()
    for a in attr_list:
        name = a.get('Name')
        value = a.get('Value')
        if value in ['true', 'false']:
            value = ast.literal_eval(value.capitalize())
        name = attr_map.get(name,name)
        attr_dict[name] = value
    return attr_dict

def dict_to_cognito(attributes,attr_map=dict()):
    """
    :param attributes: Dictionary of User Pool attribute names/values
    :return: list of User Pool attribute formatted dicts: {'Name': <attr_name>, 'Value': <attr_value>}
    """
    for k,v in attr_map.items():
        if v in attributes.keys():
            attributes[k] = attributes.pop(v)

    return [{'Name': key, 'Value': value} for key, value in attributes.items()]


class UserObj(object):

    def __init__(self, username, attribute_list, metadata=dict(),attr_map=dict()):
        """
        :param username:
        :param attribute_list:
        :param metadata: Dictionary of User metadata
        """
        self.username = username
        self.pk = username
        for k,v in cognito_to_dict(attribute_list,attr_map).items():
            setattr(self, k, v)
        for key, value in metadata.items():
            setattr(self, key.lower(), value)


class Cognito(object):

    user_class = UserObj

    def __init__(
            self, user_pool_id, client_id,user_pool_region=None,
            username=None,
            id_token=None,refresh_token=None,
            access_token=None,secret_hash=None,
            access_key=None, secret_key=None,
            ):
        """
        :param user_pool_id: Cognito User Pool ID
        :param client_id: Cognito User Pool Application client ID
        :param username: User Pool username
        :param id_token: ID Token returned by authentication
        :param refresh_token: Refresh Token returned by authentication
        :param access_token: Access Token returned by authentication
        :param access_key: AWS IAM access key
        :param secret_key: AWS IAM secret key
        """

        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.user_pool_region = user_pool_region or env('AWS_DEFAULT_REGION','us-east-1')
        self.username = username
        self.id_token = id_token
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.secret_hash = secret_hash
        self.token_type = None

        if access_key and secret_key:
            self.client = boto3.client('cognito-idp',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=self.user_pool_region
                )
        else:
            self.client = boto3.client('cognito-idp')

    def get_keys(self):
        try:
            return self.pool_jwk
        except AttributeError:
            self.pool_jwk = requests.get(
                'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(
                    self.user_pool_region,self.user_pool_id
                )).json()
            return self.pool_jwk

    def get_key(self,kid):
        keys = self.get_keys().get('keys')
        key = filter(lambda x:x.get('kid') == kid,keys)
        return key[0]

    def verify_token(self,token,id_name):
        kid = jwt.get_unverified_header(token).get('kid')

        hmac_key = self.get_key(kid)
        key = jwk.construct(hmac_key)
        message, encoded_sig = token.rsplit('.', 1)
        decoded_sig = base64url_decode(str(encoded_sig))
        verified = key.verify(message, decoded_sig)
        if verified:
            setattr(self,id_name,token)
        return verified

    def get_user_obj(self,username=None,attribute_list=[],metadata={},attr_map=dict()):
        """
        Returns the specified 
        :param username: Username of the user 
        :param attribute_list: List of tuples that represent the user's 
            attributes as returned by the admin_get_user or get_user boto3 methods
        :param metadata: Metadata about the user
        :param attr_map: Dictionary that maps the Cognito attribute names to 
        what we'd like to display to the users
        :return: 
        """
        return self.user_class(username=username,attribute_list=attribute_list,
                               metadata=metadata,attr_map=attr_map)

    def switch_session(self,session):
        """
        Primarily used for unit testing so we can take advantage of the
        placebo library (https://githhub.com/garnaat/placebo)
        :param session: boto3 session
        :return:
        """
        self.client = session.client('cognito-idp')

    def check_token(self):
        """
        Checks the exp attribute of the access_token and either refreshes
        the tokens by calling the renew_access_tokens method or does nothing
        :return: None
        """
        if not self.access_token:
            raise AttributeError('Access Token Required to Check Token')
        now = datetime.datetime.now()
        dec_access_token = jwt.get_unverified_claims(self.access_token)

        if now > datetime.datetime.fromtimestamp(dec_access_token['exp']):
            self.renew_access_token()
            return True
        return False

    def register(self, username, password,attr_map=dict(),**kwargs):
        """
        Register the user. Other base attributes from AWS Cognito User Pools
        are  address, birthdate, email, family_name (last name), gender,
        given_name (first name), locale, middle_name, name, nickname,
        phone_number, picture, preferred_username, profile, zoneinfo,
        updated at, website
        :param username: User Pool username
        :param password: User Pool password
        :param attr_map: Attribute map to Cognito's attributes
        :param kwargs: Additional User Pool attributes
        :return response: Response from Cognito

        Example response::
        {
            'UserConfirmed': True|False,
            'CodeDeliveryDetails': {
                'Destination': 'string', # This value will be obfuscated
                'DeliveryMedium': 'SMS'|'EMAIL',
                'AttributeName': 'string'
            }
        }
        """
        user_attrs = [{'Name': key, 'Value': value} for key, value in kwargs.items()]
        response = self.client.sign_up(
            ClientId=self.client_id,
            Username=username,
            Password=password,
            UserAttributes=dict_to_cognito(kwargs,attr_map)
        )
        kwargs.update(username=username, password=password)
        self._set_attributes(response, kwargs)

        response.pop('ResponseMetadata')
        return response

    def confirm_sign_up(self,confirmation_code,username=None):
        """
        Using the confirmation code that is either sent via email or text
        message.
        :param confirmation_code: Confirmation code sent via text or email
        :param username: User's username
        :return:
        """
        if not username:
            username = self.username
        self.client.confirm_sign_up(
            ClientId=self.client_id,
            Username=username,
            ConfirmationCode=confirmation_code
        )

    def admin_authenticate(self, password):
        """
        Authenticate the user using admin super privileges
        :param password: User's password
        :return:
        """
        auth_params = {
                'USERNAME': self.username,
                'PASSWORD': password
            }

        tokens = self.client.admin_initiate_auth(
            UserPoolId=self.user_pool_id,
            ClientId=self.client_id,
            # AuthFlow='USER_SRP_AUTH'|'REFRESH_TOKEN_AUTH'|'REFRESH_TOKEN'|'CUSTOM_AUTH'|'ADMIN_NO_SRP_AUTH',
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters=auth_params,
        )

        self.verify_token(tokens['AuthenticationResult']['IdToken'], 'id_token')
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.verify_token(tokens['AuthenticationResult']['AccessToken'], 'access_token')
        self.token_type = tokens['AuthenticationResult']['TokenType']

    def authenticate(self, password):
        """
        Authenticate the user using the SRP protocol
        :param password: The user's passsword
        :return:
        """
        aws = AWSSRP(username=self.username, password=password, pool_id=self.user_pool_id,
                     client_id=self.client_id, client=self.client)
        tokens = aws.authenticate_user()
        self.verify_token(tokens['AuthenticationResult']['IdToken'],'id_token')
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.verify_token(tokens['AuthenticationResult']['AccessToken'], 'access_token')
        self.token_type = tokens['AuthenticationResult']['TokenType']

    def logout(self):
        """
        Logs the user out of all clients and removes the expires_in,
        expires_datetime, id_token, refresh_token, access_token, and token_type
        attributes
        :return:
        """
        self.client.global_sign_out(
            AccessToken=self.access_token
        )

        self.id_token = None
        self.refresh_token = None
        self.access_token = None
        self.token_type = None

    def update_profile(self, attrs,attr_map=dict()):
        """
        Updates User attributes
        :param attrs: Dictionary of attribute name, values
        :param attr_map: Dictionary map from Cognito attributes to attribute 
        names we would like to show to our users
        """
        user_attrs = dict_to_cognito(attrs,attr_map)
        response = self.client.update_user_attributes(
            UserAttributes=user_attrs,
            AccessToken=self.access_token
        )

    def get_user(self,attr_map=dict()):
        """
        Returns a UserObj (or whatever the self.user_class is) by using the 
        user's access token.
        :param attr_map: Dictionary map from Cognito attributes to attribute 
        names we would like to show to our users
        :return: 
        """
        user = self.client.get_user(
                AccessToken=self.access_token
            )
        
        user_metadata = {
            'username': user.get('Username'),
            'id_token': self.id_token,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
        }
        return self.get_user_obj(username=self.username,
                                 attribute_list=user.get('UserAttributes'),
                                 metadata=user_metadata,attr_map=attr_map)

    def get_users(self,attr_map=dict()):
        """
        Returns all users for a user pool. Returns instances of the 
        self.user_class.
        :param attr_map: 
        :return: 
        """
        kwargs = {"UserPoolId":self.user_pool_id}

        response = self.client.list_users(**kwargs)
        return [self.get_user_obj(user.get('Username'),
                                  attribute_list=user.get('Attributes'),
                                  metadata={'username':user.get('Username')},
                                  attr_map=attr_map)
                for user in response.get('Users')]

    def admin_get_user(self,attr_map=dict()):
        """
        Get the user's details using admin super privileges.
        :param attr_map: Dictionary map from Cognito attributes to attribute 
        names we would like to show to our users
        :return: UserObj object
        """
        user = self.client.admin_get_user(
                           UserPoolId=self.user_pool_id,
                           Username=self.username)
        user_metadata = {
            'user_status':user.get('UserStatus'),
            'username':user.get('Username'),
            'id_token': self.id_token,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token
        }
        return self.get_user_obj(username=self.username,
                                 attribute_list=user.get('UserAttributes'),
                                 metadata=user_metadata,attr_map=attr_map)


    def send_verification(self, attribute='email'):
        """
        Sends the user an attribute verification code for the specified attribute name.
        :param attribute: Attribute to confirm
        """
        self.check_token()
        self.client.get_user_attribute_verification_code(
            AccessToken=self.access_token,
            AttributeName=attribute
        )

    def validate_verification(self, confirmation_code, attribute='email'):
        """
        Verifies the specified user attributes in the user pool.
        :param confirmation_code: Code sent to user upon intiating verification
        :param attribute: Attribute to confirm
        """
        self.check_token()
        return self.client.verify_user_attribute(
            AccessToken=self.access_token,
            AttributeName=attribute,
            Code=confirmation_code
        )

    def renew_access_token(self):
        """
        Sets a new access token on the User using the refresh token.
        """
        refresh_response = self.client.initiate_auth(
            ClientId=self.client_id,
            AuthFlow='REFRESH_TOKEN',
            AuthParameters={
                'REFRESH_TOKEN': self.refresh_token
            },
        )

        self._set_attributes(
            refresh_response,
            {
                'access_token': refresh_response['AuthenticationResult']['AccessToken'],
                'id_token': refresh_response['AuthenticationResult']['IdToken'],
                'token_type': refresh_response['AuthenticationResult']['TokenType']
            }
        )

    def initiate_forgot_password(self):
        """
        Sends a verification code to the user to use to change their password.
        """
        self.client.forgot_password(
            ClientId=self.client_id,
            Username=self.username
        )

    def confirm_forgot_password(self, confirmation_code, password):
        """
        Allows a user to enter a code provided when they reset their password
        to update their password.
        :param confirmation_code: The confirmation code sent by a user's request
        to retrieve a forgotten password
        :param password: New password
        """
        response = self.client.confirm_forgot_password(
            ClientId=self.client_id,
            Username=self.username,
            ConfirmationCode=confirmation_code,
            Password=password
        )
        self._set_attributes(response, {'password': password})

    def change_password(self, previous_password, proposed_password):
        """
        Change the User password
        """
        self.check_token()
        response = self.client.change_password(
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=self.access_token
        )
        self._set_attributes(response, {'password': proposed_password})

    def _set_attributes(self, response, attribute_dict):
        """
        Set user attributes based on response code
        :param response: HTTP response from Cognito
        :attribute dict: Dictionary of attribute name and values
        """
        status_code = response.get(
            'HTTPStatusCode',
            response['ResponseMetadata']['HTTPStatusCode']
        )
        if status_code == 200:
            for k, v in attribute_dict.items():
                setattr(self, k, v)
