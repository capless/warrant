# cognito
Python class to integrate Boto3's Cognito client with PySRP so it is easy to login users.

## Create a Cognito Instance

###Example with All Arguments
```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
        username='optional-username',
        password='optional-password',
        id_token='optional-id-token',
        refresh_token='optional-refresh-token',
        access_token='optional-access-token',
        expires_datetime='optional-expires-datetime',
        access_key='optional-access-key',secret_key='optional-secret-key'
        )
```

###Examples with Realistic Arguments

####User Pool Id and Client ID Only
```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')
```

####Username/Password
```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
        username='bob',
        password='bos-password'
        )
```

####Tokens

```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='your-id-token',
    refresh_token='your-refresh-token',
    access_token='your-access-token'
)
```

##Cognito Methods

####Register

Register a user to the user pool

**Important:** The keyword arguments used for this method depend on your user pool's configuration, and make sure the client id (app id) used has write permissions for the attriubtes you are trying to create. Example, if you want to create a user with a given_name equal to Johnson make sure the client_id you're using has permissions to edit or create given_name for a user in the pool.


```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.register('username','password',email='opt')
```

####Authenticate

Authenticates a user
 
If this method call succeeds the instance will have the following attributes **id_token**, **refresh_token**, **access_token**, **expires_in**, **expires_datetime**, and **token_type**.

```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob',password='bobs-password')

u.authenticate()
```

####Change Password

Changes the user's password

```python
from cognito import Cognito

#If you don't use your tokens then you will need to 
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.change_password('previous-password','proposed-password')
```

####Confirm Sign Up

Use the confirmation code that is sent via email or text to confirm the user's account

```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id')

u.confirm_sign_up('users-conf-code',username='bob')
```

####Update Profile

Update the user's profile

```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.update_profile({'given_name':'Edward','family_name':'Smith',})
```

####Send Verification

Send verification email or text for either the email or phone attributes.

```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.send_verification(attribute='email')
```


####Get User

Get all of the user's attributes

**Important:** Returns a UserObj project

```python
from cognito import Cognito

u = Cognito('your-user-pool-id','your-client-id',
    username='bob')

user = u.get_user()
```

####Logout

Logs the user out of all clients. Erases the access token.

```python
from cognito import Cognito

#If you don't use your tokens then you will need to 
#use your username and password and call the authenticate method
u = Cognito('your-user-pool-id','your-client-id',
    id_token='id-token',refresh_token='refresh-token',
    access_token='access-token')

u.logout()
```