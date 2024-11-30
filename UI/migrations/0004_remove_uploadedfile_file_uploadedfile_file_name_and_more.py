# Generated by Django 5.0.2 on 2024-03-11 01:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('UI', '0003_userprofile_mfa_verified'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='uploadedfile',
            name='file',
        ),
        migrations.AddField(
            model_name='uploadedfile',
            name='file_name',
            field=models.CharField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='uploadedfile',
            name='file_url',
            field=models.URLField(default=''),
        ),
    ]
