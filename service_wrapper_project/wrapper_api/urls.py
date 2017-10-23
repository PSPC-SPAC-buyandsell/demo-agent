from django.conf.urls import url, include
# from rest_framework import routers
from wrapper_api import views

# router = routers.SimpleRouter()
# router.register(r'^api/v0', views.IndyPostView, '')

urlpatterns = [
    url(r'^api/v0', views.IndyPostView.as_view()),
]
