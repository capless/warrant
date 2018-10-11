![alt text](https://s3.amazonaws.com/capless/images/warrant-small.png "Warrant - Serverless Authentication")

# Warrant

Makes working with AWS Cognito easier for Python developers.

[![Build Status](https://travis-ci.org/capless/warrant.svg?branch=master)](https://travis-ci.org/capless/warrant)

## Getting Started

- [Python Versions Supported](#python-versions-supported)
- [Install](#install)
- [Environment Variables](#environment-variables)
    - [COGNITO_JWKS](#cognito-jwks) (optional)
- [Cognito Utility Class](#cognito-utility-class) `warrant.Cognito`
    - [Cognito Methods](#cognito-methods)
        - [Register](#register)
        - [Authenticate](#authenticate)
        - [Admin Authenticate](#admin-authenticate)
        - [Initiate Forgot Password](#initiate-forgot-password)
        - [Confirm Forgot Password](#confirm-forgot-password)
        - [Change Password](#change-password)
        - [Confirm Sign Up](#confirm-sign-up)
        - [Update Profile](#update-profile)
        - [Send Verification](#send-verification)
        - [Get User Object](#get-user-object)
        - [Get User](#get-user)
        - [Get Users](#get-users)
        - [Get Group Object](#get-group-object)
        - [Get Group](#get-group)
        - [Get Groups](#get-groups)
        - [Check Token](#check-token)
        - [Logout](#logout)
- [Cognito SRP Utility](#cognito-srp-utility) `warrant.aws_srp.AWSSRP`
    - [Using AWSSRP](#using-awssrp)
- [Projects Using Warrant](#projects-using-warrant)
    - [Django Warrant](#django-warrant)
- [Authors](#authors)
- [Release Notes](#release-notes)

## Python Versions Supported

- 2.7
- 3.6

## Install

`pip install warrant`


## Environment Variables

#### COGNITO_JWKS

**Optional:** This environment variable is a dictionary that represent the well known JWKs assigned to your user pool by AWS Cognito. You can find the keys for your user pool by substituting in your AWS region and pool id for the following example.
 `https://cognito-idp.{aws-region}.amazonaws.com/{user-pool-id}/.well-known/jwks.json`
 
 **Example Value (Not Real):**
 ```commandline
COGNITO_JWKS={"keys": [{"alg": "RS256","e": "AQAB","kid": "123456789ABCDEFGHIJKLMNOP","kty": "RSA","n": "123456789ABCDEFGHIJKLMNOP","use": "sig"},{"alg": "RS256","e": "AQAB","kid": "123456789ABCDEFGHIJKLMNOP","kty": "RSA","n": "123456789ABCDEFGHIJKLMNOP","use": "sig"}]}
```
## Cognito Utility Class

### Example with All Arguments ###

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    client_secret='optional-client-secret'
    username='optional-username',
    id_token='optional-id-token',
    refresh_token='optional-refresh-token',
    access_token='optional-access-token',
    access_key='optional-access-key',
    secret_key='optional-secret-key')
```

#### Arguments

- **user_pool_id:** Cognito User Pool ID
- **client_id:** Cognito User Pool Application client ID
- **client_secret:** App client secret (if app client is configured with client secret)
- **username:** User Pool username
- **id_token:** ID Token returned by authentication
- **refresh_token:** Refresh Token returned by authentication
- **access_token:** Access Token returned by authentication
- **access_key:** AWS IAM access key
- **secret_key:** AWS IAM secret key


### Examples with Realistic Arguments ###

#### User Pool Id and Client ID Only ####

Used when you only need information about the user pool (ex. list users in the user pool)
```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')
```

#### Username

Used when the user has not logged in yet. Start with these arguments when you plan to authenticate with either SRP (authenticate) or admin_authenticate (admin_initiate_auth).
```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')
```

#### Tokens ####

Used after the user has already authenticated and you need to build a new Cognito instance (ex. for use in a view).

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='your-id-token',
    refresh_token='your-refresh-token',
    access_token='your-access-token')
```

## Cognito Methods ##

#### Register ####

Register a user to the user pool

**Important:** The arguments for `add_base_attributes` and `add_custom_attributes` methods depend on your user pool's configuration, and make sure the client id (app id) used has write permissions for the attriubtes you are trying to create. Example, if you want to create a user with a given_name equal to Johnson make sure the client_id you're using has permissions to edit or create given_name for a user in the pool.


```python
from warrant import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

u.add_base_attributes(email='you@you.com', some_random_attr='random value')

u.register('username', 'password')
```

Register with custom attributes.

Firstly, add custom attributes on 'General settings -> Attributes' page.
Secondly, set permissions on 'Generals settings-> App clients-> Show details-> Set attribute read and write permissions' page.
```python
from warrant import Cognito

u = Cognito('your-user-pool-id', 'your-client-id')

u.add_base_attributes(email='you@you.com', some_random_attr='random value')

u.add_custom_attributes(state='virginia', city='Centreville')

u.register('username', 'password')
```
##### Arguments

- **username:** User Pool username
- **password:** User Pool password
- **attr_map:** Attribute map to Cognito's attributes


#### Authenticate ####

Authenticates a user

If this method call succeeds the instance will have the following attributes **id_token**, **refresh_token**, **access_token**, **expires_in**, **expires_datetime**, and **token_type**.

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.authenticate(password='bobs-password')
```

##### Arguments

- **password:** - User's password

#### Admin Authenticate

Authenticate the user using admin super privileges

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.admin_authenticate(password='bobs-password')
```

- **password:** User's password

#### Initiate Forgot Password

Sends a verification code to the user to use to change their password.

```python
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.initiate_forgot_password()
```

##### Arguments

No arguments

#### Confirm Forgot Password

Allows a user to enter a code provided when they reset their password
to update their password.

```python
u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

u.confirm_forgot_password('your-confirmation-code','your-new-password')
```

##### Arguments

- **confirmation_code:** The confirmation code sent by a user's request
to retrieve a forgotten password
- **password:** New password

#### Change Password ####

Changes the user's password

```python
from warrant import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.change_password('previous-password','proposed-password')
```

##### Arguments

- **previous_password:** - User's previous password
- **proposed_password:** - The password that the user wants to change to.

#### Confirm Sign Up ####

Use the confirmation code that is sent via email or text to confirm the user's account

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.confirm_sign_up('users-conf-code',username='bob')
```

##### Arguments

- **confirmation_code:** Confirmation code sent via text or email
- **username:** User's username

#### Update Profile ####

Update the user's profile

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.update_profile({'given_name':'Edward','family_name':'Smith',},attr_map=dict())
```

##### Arguments

- **attrs:** Dictionary of attribute name, values
- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Send Verification ####

Send verification email or text for either the email or phone attributes.

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.send_verification(attribute='email')
```

##### Arguments

- **attribute:** - The attribute (email or phone) that needs to be verified

#### Get User Object

Returns an instance of the specified user_class.

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.get_user_obj(username='bjones',
    attribute_list=[{'Name': 'string','Value': 'string'},],
    metadata={},
    attr_map={"given_name":"first_name","family_name":"last_name"}
    )
```
##### Arguments
- **username:** Username of the user
- **attribute_list:** List of tuples that represent the user's attributes as returned by the admin_get_user or get_user boto3 methods
- **metadata: (optional)** Metadata about the user
- **attr_map: (optional)** Dictionary that maps the Cognito attribute names to what we'd like to display to the users


#### Get User

Get all of the user's attributes. Gets the user's attributes using Boto3 and uses that info to create an instance of the user_class

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

user = u.get_user(attr_map={"given_name":"first_name","family_name":"last_name"})
```

##### Arguments
- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Get Users

Get a list of the user in the user pool.


```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')

user = u.get_users(attr_map={"given_name":"first_name","family_name":"last_name"})
```

##### Arguments
- **attr_map:** Dictionary map from Cognito attributes to attribute names we would like to show to our users

#### Get Group object

Returns an instance of the specified group_class.

```python
u = Cognito('your-user-pool-id', 'your-client-id')

group_data = {'GroupName': 'user_group', 'Description': 'description',
            'Precedence': 1}

group_obj = u.get_group_obj(group_data)
```

##### Arguments
- **group_data:** Dictionary with group's attributes.

#### Get Group

Get all of the group's attributes. Returns an instance of the group_class.
Requires developer credentials.

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')

group = u.get_group(group_name='some_group_name')
```

##### Arguments
- **group_name:** Name of a group

#### Get Groups

Get a list of groups in the user pool. Requires developer credentials.

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')

groups = u.get_groups()
```

#### Check Token

Checks the exp attribute of the access_token and either refreshes the tokens by calling the renew_access_tokens method or does nothing. **IMPORTANT:** Access token is required

```python
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.check_token()
```
##### Arguments

No arguments for check_token

#### Logout ####

Logs the user out of all clients and removes the expires_in, expires_datetime, id_token, refresh_token, access_token, and token_type attributes.

```python
from warrant import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.logout()
```
##### Arguments

No arguments for check_token

## Cognito SRP Utility
The `AWSSRP` class is used to perform [SRP(Secure Remote Password protocol)](https://www.ietf.org/rfc/rfc2945.txt) authentication.
This is the preferred method of user authentication with AWS Cognito.
The process involves a series of authentication challenges and responses, which if successful,
results in a final response that contains ID, access and refresh tokens.

### Using AWSSRP
The `AWSSRP` class takes a username, password, cognito user pool id, cognito app id, an optional
client secret (if app client is configured with client secret), an optional pool_region or `boto3` client.
Afterwards, the `authenticate_user` class method is used for SRP authentication.


```python
import boto3
from warrant.aws_srp import AWSSRP

client = boto3.client('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client)
tokens = aws.authenticate_user()
```

## Projects Using Warrant

#### [Django Warrant](https://www.github.com/metametricsinc/django-warrant)

## Authors

### Brian Jinwright
**Twitter:** [@brianjinwright](https://www.twitter.com/brianjinwright)
**GitHub:** [@bjinwright](https://www.github.com/bjinwright/)

### Eric Petway
**GitHub:** [@ebpetway](https://www.github.com/ebpetway)

### Sergey Vishnikin

**GitHub:** [@armicron](https://www.github.com/armicron)

## [Release Notes](https://github.com/capless/warrant/blob/master/HISTORY.md)
