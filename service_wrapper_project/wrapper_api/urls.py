from django.conf.urls import url, include
# from rest_framework import routers
from wrapper_api import views


urlpatterns = [
    url(r'^{}'.format(views.PATH_PREFIX_SLASH), include([
        url(r'^txn/(?P<seq_no>\d+)', views.ServiceWrapper.as_view()),
        url(r'^did', views.ServiceWrapper.as_view()),

        # redundant patterns here show explicitly what service wrapper takes as POSTed tokens
        url(r'^agent-nym-lookup', views.ServiceWrapper.as_view()),
        url(r'^agent-nym-send', views.ServiceWrapper.as_view()),
        url(r'^agent-endpoint-lookup', views.ServiceWrapper.as_view()),
        url(r'^agent-endpoint-send', views.ServiceWrapper.as_view()),
        url(r'^schema-send', views.ServiceWrapper.as_view()),
        url(r'^schema-lookup', views.ServiceWrapper.as_view()),
        url(r'^claim-def-send', views.ServiceWrapper.as_view()),
        url(r'^master-secret-set', views.ServiceWrapper.as_view()),
        url(r'^claim-hello', views.ServiceWrapper.as_view()),
        url(r'^claim-create', views.ServiceWrapper.as_view()),
        url(r'^claim-store', views.ServiceWrapper.as_view()),
        url(r'^claim-request', views.ServiceWrapper.as_view()),
        url(r'^proof-request', views.ServiceWrapper.as_view()),
        url(r'^verification-request', views.ServiceWrapper.as_view()),
        url(r'^claims-reset', views.ServiceWrapper.as_view()),
    ])),
]

