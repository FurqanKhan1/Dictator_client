#!python
# log/urls.py
from django.conf.urls import url
from . import views

# We are adding a URL called /home
urlpatterns = [
    url(r'^scan/$', views.Scan.as_view(), name='scan'),
	url(r'^details/$', views.Discovery.as_view(), name='discovery'),
	url(r'^config/$', views.Config.as_view(), name='config'),
	url(r'^config_conc/$', views.Config_conc.as_view(), name='Config_conc'),
	url(r'^vul_scan/$', views.Vul_Scan.as_view(), name='vul_scan'),
	url(r'^vul_scan_conc/$',views.Vul_Scan_conc.as_view(),name='vul_scan_conc'),
	url(r'^Map/$',views.OnFly.as_view(),name='Map'),
	url(r'^Download/$',views.DownloadAll.as_view(),name='Download'),
	url(r'^Download_im/$',views.DownloadAll_im.as_view(),name='Download_im'),
	url(r'^pause/$', views.Pause_Scan.as_view(), name='pause'),
	url(r'^details_vul_scan/$', views.Polling_Scanning.as_view(), name='details_vul_scan'),
	url(r'^details_vul_scan_im/$', views.Polling_Scanning_intermediate.as_view(), name='details_vul_scan_im'),
	url(r'^details_scan_conc/$', views.Polling_Scanning_conc.as_view(), name='details_scan_conc'),
	url(r'^scans/$', views.Scans.as_view(), name='scans'),
	url(r'^Upload/$', views.Upload.as_view(), name='Upload'),
	url(r'^Merger/$', views.Merger.as_view(), name='Merger'),
	url(r'^resume_scan/$', views.Resume_Scan.as_view(), name='resume'),
    url(r'^view_intermediate/$',views.View_intermediate.as_view(),name='view_intermediate'),
	url(r'^restore_state/$', views.Restore_State.as_view(), name='restore_state'),
	url(r'^add/$', views.Add_Test_Case.as_view(), name='add'),
	url(r'^faqs/$', views.Faq.as_view(), name='faqs'),
	url(r'^ScanProfiles/',views.Profiles_.as_view()),
	url(r'^getProfile/',views.Profile_.as_view()),
	url(r'^usage/$', views.Usage.as_view(), name='usage'),
	
	
]
