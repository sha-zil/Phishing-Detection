from django.urls import path
from . import views

urlpatterns = [
    # by default, when the base url is opened, it executes the home method in views.py which then displays index.html
    path('', views.home, name='home'),
    # when the url matches .../result, as requested by the index.html page, it executes the result method in views.py which then displays result.html
    path('result', views.result, name='result')
]
