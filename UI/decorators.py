# decorators.py

from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import Group
from django.http import HttpResponseForbidden
from functools import wraps

def manager_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.groups.filter(name='Manager').exists():
            return view_func(request, *args, **kwargs)
        else:
            # Redirect or show a permission denied page
            return HttpResponseForbidden("You do not have permission to access this page.")
        
    return _wrapped_view

def manager_or_admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.groups.filter(name__in=['Manager', 'Admin']).exists():
            return view_func(request, *args, **kwargs)
        else:
            # Redirect or show a permission denied page
            return HttpResponseForbidden("You do not have permission to access this page.")
        
    return _wrapped_view