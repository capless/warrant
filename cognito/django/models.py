from django.contrib import auth
from django.conf import settings
from django.db import models


class ApiKeyManager(models.Manager):
    def get_or_create_apikey(self, user_id, apikey, return_inactive=False):
        """
        Return an active ApiKey instance,
        creating a new one if necessary.
        :param apikey: String of new apikey
        :param return_inactive: Return existing inactive key if True
        :returns: (object, created) 
        """
        User = auth.get_user_model()
        user = User.objects.get(id=user_id)

        existing_keys = ApiKey.objects.filter(user_id=user_id)
        if not existing_keys.exists():
            new_key = ApiKey.objects.create(apikey=apikey, user_id=user_id, active=True)
            return (new_key, True)
     
        if return_inactive and existing_keys.filter(apikey=apikey).exists():
            return (existing_keys.get(apikey=apikey), False)
        elif not return_inactive and existing_keys.filter(apikey=apikey).exists():
            existing_key = existing_keys.get(apikey=apikey)
            if existing_key.active:
                return existing_key, False
            else:
                return None, False

        for key in existing_keys.filter(active=True):
            if key.apikey == apikey:
                return (key, False)
            key.active = False
            key.save()
        new_key = ApiKey.objects.create(apikey=apikey, user_id=user_id, active=True)
        return (new_key, True)
        

class ApiKey(models.Model):
    apikey = models.CharField(max_length=255, unique=True)
    user_id = models.IntegerField()
    active = models.BooleanField(default=False)

    objects = ApiKeyManager()

    class Meta:
        unique_together = ('user_id', 'apikey', 'active')
