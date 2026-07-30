from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', TemplateView.as_view(template_name='index.html'), name='landing'),
    path('accounts/', include('accounts.urls')),
    path('vault/', include('vault.urls')),
    path('sharing/', include('sharing.urls')),
    path('docs/', TemplateView.as_view(template_name='docs/index.html'), name='docs'),
]

urlpatterns += [
    re_path(r'^%s(?P<path>.*)$' % settings.STATIC_URL.lstrip('/'), serve, {'document_root': settings.STATIC_ROOT}),
]
if settings.DEBUG:
    urlpatterns += [
        re_path(r'^assets/(?P<path>.*)$', serve, {'document_root': settings.BASE_DIR / 'assets'}),
    ]
