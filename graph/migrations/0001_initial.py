# Generated by Django 5.0.2 on 2024-03-04 17:21

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Create_acnt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=30)),
                ('email', models.EmailField(max_length=254)),
                ('pwd', models.CharField(max_length=12)),
                ('con_pwd', models.CharField(max_length=12)),
            ],
        ),
    ]