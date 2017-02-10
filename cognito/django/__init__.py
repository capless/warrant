from django.contrib.auth.signals import user_logged_in


def add_user_tokens(sender, user, **kwargs):
    """
    Add user tokens to the session upon login
    """
    request = kwargs['request']
    request.session['ACCESS_TOKEN'] = user.access_token
    request.session['ID_TOKEN'] = user.id_token
    request.session['REFRESH_TOKEN'] = user.refresh_token
    request.session.save()

user_logged_in.connect(add_user_tokens)
