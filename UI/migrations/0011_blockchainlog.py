# Generated by Django 5.0.2 on 2024-04-08 00:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('UI', '0010_statuslog_delete_logentry'),
    ]

    operations = [
        migrations.CreateModel(
            name='BLockchainLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('logger_name', models.CharField(max_length=100)),
                ('level', models.PositiveSmallIntegerField(choices=[(0, 'NotSet'), (20, 'Info'), (30, 'Warning'), (10, 'Debug'), (40, 'Error'), (50, 'Fatal')], db_index=True, default=40)),
                ('msg', models.TextField()),
                ('trace', models.TextField(blank=True, null=True)),
                ('create_datetime', models.DateTimeField(auto_now_add=True, verbose_name='Created at')),
                ('user', models.CharField(blank=True, max_length=100, null=True)),
            ],
            options={
                'verbose_name': 'Logging',
                'verbose_name_plural': 'Logging',
                'ordering': ('-create_datetime',),
            },
        ),
    ]
