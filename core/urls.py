from django.urls import path, include
from .views import *
from rest_framework.routers import DefaultRouter
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework.authtoken import views

router = DefaultRouter()
router.register('Login', AuthViewSet, basename="Login")
router.register('Logout', LogoutView, basename="Logout")
router.register('Retruteur', UserTmpViewset, basename="Retruteur")

urlpatterns = [
    path('', include(router.urls)),
    path('api-token-auth/', views.obtain_auth_token),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),

    # path('dj-rest-auth/', include('dj_rest_auth.urls')),
]