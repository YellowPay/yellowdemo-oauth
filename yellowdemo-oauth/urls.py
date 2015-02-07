from django.conf.urls import patterns, include, url
import demo.views

urlpatterns = patterns('',
    url(r'^$', demo.views.home),
    url(r'^invoice/$', demo.views.invoice),
    url(r'^ipn/$', demo.views.ipn),
)