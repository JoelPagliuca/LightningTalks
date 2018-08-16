from django.contrib import admin
from django.urls import path

from mysite.views import demo

urlpatterns = [
    path('admin/', admin.site.urls),
    path('demo/', demo)
]
