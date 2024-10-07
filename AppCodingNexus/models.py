from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    display_photo = models.ImageField(upload_to='profile_pics/', default='default.jpg')
    firstname = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    gender = models.CharField(max_length=10, null=True ,blank=True)
    birthmonth = models.CharField(max_length=15, null=True, blank=True)
    birthday = models.CharField(max_length=15, null=True, blank=True)
    birthyear = models.CharField(max_length=15, null=True, blank=True)
    role = models.CharField(max_length=20)

    def __str__(self):
        return self.user.username
