from django import forms


class ProfileForm(forms.Form):
    name = forms.CharField(max_length=200,required=True)
    email = forms.EmailField(required=True)
    phone = forms.CharField(max_length=30,required=True)
    gender = forms.ChoiceField(choices=(('Female','Female'),('Male','Male')),required=True)
    address = forms.CharField(max_length=200,required=True)
    preferred_username = forms.CharField(max_length=200,required=True)