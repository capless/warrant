from django.conf import settings
from cognito import Cognito


def get_cognito(request):

    c = Cognito(settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,
                access_token=request.session.get('ACCESS_TOKEN'),
                id_token=request.session.get('ID_TOKEN'),
                refresh_token=request.session.get('REFRESH_TOKEN'))
    changed = c.check_token()
    if changed:
        request.session['ACCESS_TOKEN'] = c.access_token
        request.session['REFRESH_TOKEN'] = c.refresh_token
        request.session['ID_TOKEN'] = c.id_token
        request.save()
    return c
