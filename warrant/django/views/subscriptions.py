import boto3
from django.contrib import messages

from django.contrib.auth.mixins import LoginRequiredMixin, \
    UserPassesTestMixin
from django.http import Http404
from django.urls import reverse_lazy
from django.views.generic import FormView
from django.views.generic.list import MultipleObjectMixin, ListView

from django.conf import settings
from warrant import UserObj, Cognito
from warrant.django.forms import APIKeySubscriptionForm


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
        try:
            u = self.get_user_object()
        except KeyError:
            raise Http404
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
                         FormView):
    template_name = 'warrant/admin-subscriptions.html'
    form_class = APIKeySubscriptionForm

    def get_success_url(self):
        return reverse_lazy('admin-cognito-user',args=[self.kwargs.get('username')])

    def test_func(self):
        return self.request.user.has_perm('can_edit')

    def get_user_object(self):
        return Cognito(settings.COGNITO_USER_POOL_ID,settings.COGNITO_APP_ID,
                      username=self.kwargs.get('username')).admin_get_user(
            attr_map=settings.COGNITO_ATTR_MAPPING)

    def get_context_data(self, **kwargs):
        kwargs['object_list'] = self.object_list = self.get_queryset()
        context = super(AdminSubscriptions, self).get_context_data(**kwargs)
        return context

    def get_form_kwargs(self):
        kwargs = super(AdminSubscriptions, self).get_form_kwargs()
        kwargs.update({'plans':self.client.get_usage_plans().get('items',[]),
                'users_plans':[p.get('id') for p in self.get_queryset()]})
        return kwargs

    def form_invalid(self, form):

        return super(AdminSubscriptions, self).form_invalid(form)

    def form_valid(self, form):
        self.client.create_usage_plan_key(
            usagePlanId=form.cleaned_data['plan'],
            keyId=self.get_user_object().api_key_id,
            keyType='API_KEY'
        )
        messages.success(self.request,'Addedd subscription successfully.')
        return super(AdminSubscriptions, self).form_valid(form)