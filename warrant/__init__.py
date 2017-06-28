import ast
import boto3
import datetime
import requests

from envs import env
from jose import jwt, JWTError

from .aws_srp import AWSSRP
from .exceptions import TokenVerificationException

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

    def __init__(self, username, attribute_list, cognito_obj, metadata=dict(),attr_map=dict()):
        """
        :param username:
        :param attribute_list:
        :param metadata: Dictionary of User metadata
        """
        self.username = username
        self.pk = username
        self._cognito = cognito_obj
        self._attr_map = attr_map
        self._data = cognito_to_dict(attribute_list,self._attr_map)
        self.sub = self._data.pop('sub',None)
        self.email_verified = self._data.pop('email_verified',None)
        self.phone_number_verified = self._data.pop('phone_number_verified',None)
        self._metadata = metadata

    def __repr__(self):
        return '<{class_name}: {uni} >'.format(
            class_name=self.__class__.__name__, uni=self.__unicode__())

    def __unicode__(self):
        return self.username

    def __getattr__(self, name):
        if name in list(self.__dict__.get('_data',{}).keys()):
            return self._data.get(name)
        if name in list(self.__dict__.get('_metadata',{}).keys()):
            return self._metadata.get(name)

    def __setattr__(self, name, value):
        if name in list(self.__dict__.get('_data',{}).keys()):
            self._data[name] = value
        else:
            super(UserObj, self).__setattr__(name, value)

    def save(self,admin=False):
        if admin:
            self._cognito.admin_update_profile(self._data, self._attr_map)
            return
        self._cognito.update_profile(self._data,self._attr_map)

    def delete(self,admin=False):
        if admin:
            self._cognito.admin_delete_user()
            return
        self._cognito.delete_user()


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
            #Check for the dictionary in environment variables.
            pool_jwk_env = env('COGNITO_JWKS', {},var_type='dict')
            if len(pool_jwk_env.keys()) > 0:
                self.pool_jwk = pool_jwk_env
                return self.pool_jwk
            #If it is not there use the requests library to get it
            self.pool_jwk = requests.get(
                'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(
                    self.user_pool_region,self.user_pool_id
                )).json()
            return self.pool_jwk

    def get_key(self,kid):
        keys = self.get_keys().get('keys')
        key = list(filter(lambda x:x.get('kid') == kid,keys))
        return key[0]

    def verify_token(self,token,id_name,token_use):
        kid = jwt.get_unverified_header(token).get('kid')
        unverified_claims = jwt.get_unverified_claims(token)
        token_use_verified = unverified_claims.get('token_use') == token_use
        if not token_use_verified:
            raise TokenVerificationException('Your {} token use could not be verified.')
        hmac_key = self.get_key(kid)
        try:
            verified = jwt.decode(token,hmac_key,algorithms=['RS256'],
                   audience=unverified_claims.get('aud'),
                   issuer=unverified_claims.get('iss'))
        except JWTError:
            raise TokenVerificationException('Your {} token could not be verified.')
        
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
                               cognito_obj=self,
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

        self.verify_token(tokens['AuthenticationResult']['IdToken'], 'id_token','id')
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.verify_token(tokens['AuthenticationResult']['AccessToken'], 'access_token','access')
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
        self.verify_token(tokens['AuthenticationResult']['IdToken'],'id_token','id')
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.verify_token(tokens['AuthenticationResult']['AccessToken'], 'access_token','access')
        self.token_type = tokens['AuthenticationResult']['TokenType']

    def new_password_challenge(self, password, new_password):
        """
        Respond to the new password challenge using the SRP protocol
        :param password: The user's current passsword
        :param password: The user's new passsword
        """
        aws = AWSSRP(username=self.username, password=password, pool_id=self.user_pool_id,
                     client_id=self.client_id, client=self.client)
        tokens = aws.set_new_password_challenge(new_password)
        self.id_token = tokens['AuthenticationResult']['IdToken']
        self.refresh_token = tokens['AuthenticationResult']['RefreshToken']
        self.access_token = tokens['AuthenticationResult']['AccessToken']
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

    def admin_update_profile(self, attrs, attr_map=dict()):
        user_attrs = dict_to_cognito(attrs, attr_map)
        self.client.admin_update_user_attributes(
            UserPoolId = self.user_pool_id,
            Username = self.username,
            UserAttributes = user_attrs
        )

    def update_profile(self, attrs,attr_map=dict()):
        """
        Updates User attributes
        :param attrs: Dictionary of attribute name, values
        :param attr_map: Dictionary map from Cognito attributes to attribute
        names we would like to show to our users
        """
        user_attrs = dict_to_cognito(attrs,attr_map)
        self.client.update_user_attributes(
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
            'enabled': user.get('Enabled'),
            'user_status':user.get('UserStatus'),
            'username':user.get('Username'),
            'id_token': self.id_token,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token
        }
        return self.get_user_obj(username=self.username,
                                 attribute_list=user.get('UserAttributes'),
                                 metadata=user_metadata,attr_map=attr_map)

    def admin_create_user(self, username, temporary_password='', attr_map=dict(), **kwargs):
        """
        Create a user using admin super privileges.
        :param username: User Pool username
        :param temporary_password: The temporary password to give the user.
        Leave blank to make Cognito generate a temporary password for the user.
        :param attr_map: Attribute map to Cognito's attributes
        :param kwargs: Additional User Pool attributes
        :return response: Response from Cognito
        """
        response = self.client.admin_create_user(
            UserPoolId=self.user_pool_id,
            Username=username,
            UserAttributes=dict_to_cognito(kwargs, attr_map),
            TemporaryPassword=temporary_password,
        )
        kwargs.update(username=username)
        self._set_attributes(response, kwargs)

        response.pop('ResponseMetadata')
        return response

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


    def delete_user(self):

        self.client.delete_user(
            AccessToken=self.access_token
        )


    def admin_delete_user(self):
        self.client.admin_delete_user(
            UserPoolId=self.user_pool_id,
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
