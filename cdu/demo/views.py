from django.shortcuts import render
from django.views.generic import FormView, TemplateView
from django.urls import reverse


class UserView(TemplateView):
    template_name = 'user_info.html'
    