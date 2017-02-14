# Cognito

Python utility class to integrate Boto3's Cognito client with PySRP so it is
easy to login users with or without SRP (secure remote password protocol).
Included is a Django authentication backend that uses the utility class to
handle password verification and fetching of user attributes.

## Using the CognitoUserPoolAuthBackend
1. In your Django project settings file, add the dotted path of
`CognitoUserPoolAuthBackend` to your list of `AUTHENTICATION_BACKENDS`.
Keep in mind that Django will attempt to authenticate a user using
each backend listed, in the order listed until successful.

```python
AUTHENTICATION_BACKENDS = [
    'cognito.django.backend.CognitoUserPoolAuthBackend',
    ...
]
```

2. Set `COGNITO_USER_POOL_ID` and `COGNITO_APP_ID` in your settings file as well.
Your User Pool ID can be found in the Pool Details tab in the AWS console.
Your App ID is found in the Apps tab, listed as "App client id".

Check the cdu/demo directory for an example project.

### Customizing CognitoUserPoolAuthBackend Behavior
Create your own backend class that inhereits from `CognitoUserPoolAuthBackend`.

Setting the class variable `create_unknown_user` to `False` prevents the backend
from creating a new local Django user and only updates existing users.

Setting the class variable `supports_inactive_user` to `True` allows
Cognito Users with a status listed in `INACTIVE_USER_STATUS` to authenticate.

