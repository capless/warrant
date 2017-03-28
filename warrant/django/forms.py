from django import forms


class ProfileForm(forms.Form):
    name = forms.CharField(max_length=200,required=True)
    email = forms.EmailField(required=True)
    phone_number = forms.CharField(max_length=30,required=True)
    gender = forms.ChoiceField(choices=(('female','Female'),('male','Male')),required=True)
    address = forms.CharField(max_length=200,required=True)
    preferred_username = forms.CharField(max_length=200,required=True)
    api_key = forms.CharField(max_length=200, required=False)
    api_key_id = forms.CharField(max_length=200, required=False)


