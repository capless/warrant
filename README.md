# Warrant

Makes working with AWS Cognito easier for Python developers.

[![Build Status](https://travis-ci.org/capless/warrant.svg?branch=master)](https://travis-ci.org/capless/warrant)

## Getting Started

- [Cognito Utility Class](#cognito-utility-class) `warrant.Cognito`
- [Cognito SRP Utility](#cognito-srp-utility) `warrant.aws_srp.AWSSRP`
- [Django Utilities](#django-utilities)
    - [Auth Backend](#django-auth-backends)
    - [Profile Views](#profile-views)
    - [API Gateway Integration](#api-gateway-integration)

## Create a Cognito Instance ##

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
```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')
```

#### Username/Password ####
```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
        username='bob',
        password='bos-password'
        )
```

#### Tokens ####

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

u.register('username','password',email='opt')
```

#### Authenticate ####

Authenticates a user

If this method call succeeds the instance will have the following attributes **id_token**, **refresh_token**, **access_token**, **expires_in**, **expires_datetime**, and **token_type**.

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob',password='bobs-password')

u.authenticate()
```

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

#### Confirm Sign Up ####

Use the confirmation code that is sent via email or text to confirm the user's account

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.confirm_sign_up('users-conf-code',username='bob')
```

#### Update Profile ####

Update the user's profile

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.update_profile({'given_name':'Edward','family_name':'Smith',})
```

#### Send Verification ####

Send verification email or text for either the email or phone attributes.

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.send_verification(attribute='email')
```


#### Get User ####

Get all of the user's attributes

**Important:** Returns a UserObj project

```python
from warrant import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

user = u.get_user()
```

#### Logout ####

Logs the user out of all clients. Erases the access token.

```python
from warrant import Cognito

#If you don't use your tokens then you will need to
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.logout()
```

## Django Utilities
### Using the CognitoBackend
1. In your Django project settings file, add the dotted path of
`CognitoBackend` to your list of `AUTHENTICATION_BACKENDS`.
Keep in mind that Django will attempt to authenticate a user using
each backend listed, in the order listed until successful.

    ```python
    AUTHENTICATION_BACKENDS = [
        'cognito.django.backend.CognitoBackend',
        ...
    ]
    ```
2. Set `COGNITO_USER_POOL_ID` and `COGNITO_APP_ID` in your settings file as well.
Your User Pool ID can be found in the Pool Details tab in the AWS console.
Your App ID is found in the Apps tab, listed as "App client id".

3. Set `COGNITO_ATTR_MAPPING` in your settings file to a dictionary mapping a
Cognito attribute name to a Django User attribute name. Defaults to:
    ```python
    {
        'email': 'email',
        'given_name': 'first_name',
        'family_name': 'last_name',
    }
    ```

### CognitoBackend Behavior ###
Since the username of a Cognito User can never change,
this is used by the backend to match a Cognito User with a local Django
User.

If a Django user is not found, one is created using the attributes
fetched from Cognito. If an existing Django user is found, their
attributes are updated.

Upon successful login, the three identity tokens returned from Cognito
(ID token, Refresh token, Access token) are stored in the user's request
session.

Check the cdu/demo directory for an example project with a login and
user details page.

### Customizing CognitoBackend Behavior ###
Create your own backend class that inhereits from `CognitoBackend`.

Setting the class variable `create_unknown_user` to `False` prevents the backend
from creating a new local Django user and only updates existing users.

Setting the class variable `supports_inactive_user` to `True` allows
Cognito Users with a status listed in `INACTIVE_USER_STATUS` to authenticate.
