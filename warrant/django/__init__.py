from django import VERSION as DJANGO_VERSION
from django.contrib.auth.signals import user_logged_in


def add_user_tokens(sender, user, **kwargs):
    """
    Add Cognito tokens to the session upon login
    """
    if user.backend == 'warrant.django.backend.CognitoBackend':
        request = kwargs['request']
        request.session['ACCESS_TOKEN'] = user.access_token
        request.session['ID_TOKEN'] = user.id_token
        request.session['REFRESH_TOKEN'] = user.refresh_token
        request.session['API_KEY'] = getattr(user, 'api_key', None)
        request.session['API_KEY_ID'] = getattr(user, 'api_key_id', None)
        request.session.save()

# If using Django 1.11 or higher, CognitoUserPoolAuthBackend
# handles storing the tokens in the session.
if DJANGO_VERSION[1] < 11:
    user_logged_in.connect(add_user_tokens)
