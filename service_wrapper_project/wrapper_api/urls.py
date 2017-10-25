from django.conf.urls import url, include
# from rest_framework import routers
from wrapper_api import views

# router = routers.SimpleRouter()
# router.register(r'^api/v0', views.IndyPostView, '')

urlpatterns = [
    url(r'^api/v0/txn/(?P<seq_no>\d+)', views.IndyGet.as_view()),
    url(r'^api/v0/txn/', views.IndyGet.as_view()),
    # url(r'^api/v0/did', views.IndyGetDid.as_view()),
    url(r'^api/v0/(?P<token_type>.*)', views.IndyPost.as_view())
]
