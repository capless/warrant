import boto3

from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.module_loading import import_string
from django.views.generic import FormView
from django.views.generic.list import MultipleObjectMixin

from django.conf import settings
from warrant import UserObj

class MySubsriptions(LoginRequiredMixin,MultipleObjectMixin,FormView):
    template_name = 'warrant/account/subscriptions.html'
    client = boto3.client('apigateway')

    def get_form_class(self):
        return import_string(settings.WARRANT_SUBSCRIPTION_FORM)


    def get_user_object(self):
        cog_client = boto3.client('cognito-idp')
        user = cog_client.get_user(AccessToken=self.request.user.access_token)
        u = UserObj(username=user.get('UserAttributes').get('username'),
                    attribute_list=user.get('UserAttributes'))
        return u

    def get_queryset(self):
        self.get_user_object()
        all_plans = self.client.get_usage_plans()
        my_plans = self.client.get_usage_plans()








