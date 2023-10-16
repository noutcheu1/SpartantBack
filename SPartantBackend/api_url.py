from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
   openapi.Info(
      title="Myjob API",
      default_version='v1',
      description="Documentation de l'api Myjob pour le Tp de INF3055 ",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="joran.noutcheu@facsciences-uy1.cm"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)


urlpatterns = [
    path('v1/', include(('core.urls', 'core'))),
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
]