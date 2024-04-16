from django.db import models

# Create your models here.
class Create_acnt(models.Model):
    name=models.CharField(max_length=30)
    email=models.EmailField(unique=True)
    pwd=models.CharField(max_length=12)
    con_pwd=models.CharField(max_length=12)
    def __str__(self):
        return self.name
