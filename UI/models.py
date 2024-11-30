import logging
from django.db import models
from six import python_2_unicode_compatible
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import *

class UploadedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255, default='')
    file_url = models.URLField(max_length=200, default='')
    shared = models.BooleanField(default=False)
    file_hash = models.CharField(max_length=200, default='')

    def __str__(self):
        return self.file_name
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mfa_enabled = models.BooleanField(default=False)
    mfa_verified = models.BooleanField(default=False) 

    def __str__(self):
        return self.user.username



LOG_LEVELS = (
    (logging.NOTSET, _('NotSet')),
    (logging.INFO, _('Info')),
    (logging.WARNING, _('Warning')),
    (logging.DEBUG, _('Debug')),
    (logging.ERROR, _('Error')),
    (logging.FATAL, _('Fatal')),
)


@python_2_unicode_compatible
class StatusLog(models.Model):
    logger_name = models.CharField(max_length=100)
    level = models.PositiveSmallIntegerField(choices=LOG_LEVELS, default=logging.ERROR, db_index=True)
    msg = models.TextField()
    trace = models.TextField(blank=True, null=True)
    create_datetime = models.DateTimeField(auto_now_add=True, verbose_name='Created at')

    user = models.CharField(max_length=100,blank=True, null=True)

    def __str__(self):
        return self.msg

    class Meta:
        ordering = ('-create_datetime',)
        verbose_name_plural = verbose_name = 'Logging'


LOG_LEVELS = (
    (logging.NOTSET, _('NotSet')),
    (logging.INFO, _('Info')),
    (logging.WARNING, _('Warning')),
    (logging.DEBUG, _('Debug')),
    (logging.ERROR, _('Error')),
    (logging.FATAL, _('Fatal')),
)


@python_2_unicode_compatible
class BLockchainLog(models.Model):
    logger_name = models.CharField(max_length=100)
    level = models.PositiveSmallIntegerField(choices=LOG_LEVELS, default=logging.ERROR, db_index=True)
    msg = models.TextField()
    trace = models.TextField(blank=True, null=True)
    create_datetime = models.DateTimeField(auto_now_add=True, verbose_name='Created at')

    user = models.CharField(max_length=100,blank=True, null=True)

    def __str__(self):
        return self.msg

    class Meta:
        ordering = ('-create_datetime',)
        verbose_name_plural = verbose_name = 'Logging'
