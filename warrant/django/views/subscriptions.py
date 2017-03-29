import boto3

from django.contrib.auth.mixins import LoginRequiredMixin, \
    UserPassesTestMixin
from django.utils.module_loading import import_string
from django.views.generic import FormView
from django.views.generic.list import MultipleObjectMixin, ListView

from django.conf import settings
from warrant import UserObj, Cognito


class GetCognitoUserMixin(object):
    client = boto3.client('apigateway')

    def get_user_object(self):
        cog_client = boto3.client('cognito-idp')
        user = cog_client.get_user(
            AccessToken=self.request.session['ACCESS_TOKEN'])
        u = UserObj(username=user.get('UserAttributes')[0].get('username'),
                    attribute_list=user.get('UserAttributes'),
                    attr_map=settings.COGNITO_ATTR_MAPPING)
        return u

    def get_queryset(self):
        u = self.get_user_object()
        my_plans = self.client.get_usage_plans(keyId=u.api_key_id)
        return my_plans.get('items',[])


class MySubsriptions(LoginRequiredMixin,GetCognitoUserMixin,ListView):
    template_name = 'warrant/subscriptions.html'


class AdminListUsers(UserPassesTestMixin,ListView):
    template_name = 'warrant/admin-list-users.html'

    def test_func(self):
        return self.request.user.is_staff

    def get_queryset(self):
        response = Cognito(settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID)\
            .get_users(attr_map=settings.COGNITO_ATTR_MAPPING)
        return response


class AdminSubscriptions(UserPassesTestMixin,GetCognitoUserMixin,
                         MultipleObjectMixin,FormView):
    template_name = 'warrant/admin-subscriptions.html'


    def test_func(self):
        return self.request.user.has_perm('can_edit')

    def get_form_class(self):
        return import_string(settings.WARRANT_SUBSCRIPTION_FORM)

    def get_context_data(self, **kwargs):
        kwargs['object_list'] = self.object_list = self.get_queryset()
        context = super(AdminSubscriptions, self).get_context_data(**kwargs)
        return context

    def form_valid(self, form):
        
        super(AdminSubscriptions, self).form_valid(form)