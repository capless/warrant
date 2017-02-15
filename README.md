# Cognito

Python utility class to integrate Boto3's Cognito client with PySRP so it is
easy to login users with or without SRP (secure remote password protocol).
Included is a Django authentication backend that uses the utility class to
handle password verification and fetching of user attributes.

## Using the CognitoBackend
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

### CognitoBackend Behavior
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

### Customizing CognitoBackend Behavior
Create your own backend class that inhereits from `CognitoBackend`.

Setting the class variable `create_unknown_user` to `False` prevents the backend
from creating a new local Django user and only updates existing users.

Setting the class variable `supports_inactive_user` to `True` allows
Cognito Users with a status listed in `INACTIVE_USER_STATUS` to authenticate.

