from django.conf import settings
from warrant import Cognito


def cognito_to_dict(attr_list,mapping):
    user_attrs = dict()
    for i in attr_list:
        name = mapping.get(i.get('Name'))
        if name:
            value = i.get('Value')
            user_attrs[name] = value
    return user_attrs

def user_obj_to_django(user_obj):
    c_attrs = settings.COGNITO_ATTR_MAPPING
    user_attrs = dict()
    for k,v in user_obj.__dict__.iteritems():
        dk = c_attrs.get(k)
        if dk:
            user_attrs[dk] = v
    return user_attrs

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
        request.session.save()
    return c

