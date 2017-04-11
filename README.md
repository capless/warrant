# Warrant

Makes working with AWS Cognito easier for Python developers.

[![Build Status](https://travis-ci.org/capless/warrant.svg?branch=master)](https://travis-ci.org/capless/warrant)

## Getting Started

- [Cognito Utility Class](#cognito-utility-class) `warrant.Cognito`
- [Cognito SRP Utility](#cognito-srp-utility) `warrant.aws_srp.AWSSRP`
    - [Using AWSSRP](#using-awssrp)
- [Django Utilities](#django-utilities)
    - [Auth Backend](#django-auth-backend) `warrant.django.backend.CognitoBackend`
        - [Using the CognitoBackend](#using-the-cognitobackend)
        - [CognitoBackend Behavior](#cognitobackend-behavior)
        - [Customizing CognitoBackend Behavior](#customizing-cognitobackend-behavior)
    - [Profile Views](#profile-views)
    - [API Gateway Integration](#api-gateway-integration)
        - [API Key Middleware](#api-key-middleware) `warrant.django.middleware.APIKeyMiddleware`

## Cognito Utility Class

### Example with All Arguments ###

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
        username='optional-username',
        id_token='optional-id-token',
        refresh_token='optional-refresh-token',
        access_token='optional-access-token',
        access_key='optional-access-key',
        secret_key='optional-secret-key'
        )
```

#### Arguments

- **user_pool_id:** Cognito User Pool ID
- **client_id:** Cognito User Pool Application client ID
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
        username='bob',
        )
```

#### Tokens ####

Used after the user has already authenticated and you need to build a new Cognito instance (ex. for use in a view).

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='your-id-token',
    refresh_token='your-refresh-token',
    access_token='your-access-token'
)
```

## Cognito Methods ##

#### Register ####

Register a user to the user pool

**Important:** The keyword arguments used for this method depend on your user pool's configuration, and make sure the client id (app id) used has write permissions for the attriubtes you are trying to create. Example, if you want to create a user with a given_name equal to Johnson make sure the client_id you're using has permissions to edit or create given_name for a user in the pool.


```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.register('username','password',email='you@you.com',some_random_attr='random value') #**kwargs are the other attributes that should be set ex. email, given_name, family_name
```
##### Arguments

- **username:** User Pool username
- **password:** User Pool password
- **attr_map:** Attribute map to Cognito's attributes
- **kwargs:** Additional User Pool attributes ex. **{'email':'you@you.com'}


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
The `AWSSRP` class takes a username, password, cognito user pool id, cognito app id, and an optional  
`boto3` client. Afterwards, the `authenticate_user` class method is used for SRP authentication.


```python
import boto3
from warrant.aws_srp import AWSSRP

client = boto3('cognito-idp')
aws = AWSSRP(username='username', password='password', pool_id='user_pool_id',
             client_id='client_id', client=client)
tokens = aws.authenticate_user()
```

## Django Utilities
### Django Auth Backend
#### Using the CognitoBackend
1. In your Django project settings file, add the dotted path of
`CognitoBackend` to your list of `AUTHENTICATION_BACKENDS`.
Keep in mind that Django will attempt to authenticate a user using
each backend listed, in the order listed until successful.

    ```python
    AUTHENTICATION_BACKENDS = [
        'warrant.django.backend.CognitoBackend',
        ...
    ]
    ```
2. Set `COGNITO_USER_POOL_ID` and `COGNITO_APP_ID` in your settings file as well.
Your User Pool ID can be found in the Pool Details tab in the AWS console.
Your App ID is found in the Apps tab, listed as "App client id".

3. Set `COGNITO_ATTR_MAPPING` in your settings file to a dictionary mapping a
Cognito attribute name to a Django User attribute name.  
If your Cognito User Pool has any custom attributes, it is automatically  
prefixed with `custom:`. Therefore, you will want to add a mapping to your  
mapping dictionary as such `{'custom:custom_attr': 'custom_attr'}`.  
Defaults to:
    ```python
    {
        'email': 'email',
        'given_name': 'first_name',
        'family_name': 'last_name',
    }
    ```
4. Optional - Set `CREATE_UNKNOWN_USERS` to `True` or `False`, depending on if  
you wish local Django users to be created upon successful login. If set to `False`,  
only existing local Django users are updated.  
Defaults to `True`.

#### CognitoBackend Behavior
Since the username of a Cognito User can never change,
this is used by the backend to match a Cognito User with a local Django
User.

If a Django user is not found, one is created using the attributes
fetched from Cognito. If an existing Django user is found, their
attributes are updated.  

If the boto3 client comes back with either a `NotAuthorizedException` or  
`UserNotFoundException`, then `None` is returned instead of a User.  
Otherwise, the exception is raised.

Upon successful login, the three identity tokens returned from Cognito
(ID token, Refresh token, Access token) are stored in the user's request
session. In Django >= 1.11, this is done directly in the backend class. 
Otherwise, this is done via the `user_logged_in` signal.

Check the django/demo directory for an example app with a login and
user details page.

#### Customizing CognitoBackend Behavior
Setting the Django setting `CREATE_UNKNOWN_USERS` to `False` prevents the backend
from creating a new local Django user and only updates existing users.  

If you create your own backend class that inhereits from `CognitoBackend`, you may  
want to also create your own custom `user_logged_in` so that it checks  
for the name of your custom class.

### API Gateway Integration

#### API Key Middleware
The `APIKeyMiddleware` checks for a `HTTP_AUTHORIZATION_ID` header  
in the request and attaches it to the request object as `api_key`.

