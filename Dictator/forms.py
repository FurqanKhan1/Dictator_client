

from django import forms

from django.core.validators import RegexValidator
from log import validators as v
#import log.validators as v

class ScanAttributes(forms.Form):
	"""
	Objective :
	This class validates and transforms the scan attributes/inputs which are needed to begin a new scan
	"""
	Project_name= forms.CharField(required=True,max_length=100,validators=[v.Validators().Project])
	Ip_range= forms.CharField(required=True,validators=[v.Validators().IP])
	Port_range= forms.CharField(required=True,validators=[v.Validators().Port])
	Switch= forms.CharField(required=True,validators=[v.Validators().decimal])
	Mode= forms.CharField(required=True,validators=[v.Validators().Project])
	profile_value=forms.CharField(required=True,validators=[v.Validators().Project])
	profile_json=forms.CharField(required=False)
	edit_profile=forms.CharField(required=True,validators=[v.Validators().decimal])


class ProfileAttributes(forms.Form):
	"""
	Objective :
	This class validates and transforms the scan attributes/inputs which are needed to begin a new scan
	"""
	Profile_name= forms.CharField(required=True,max_length=100,validators=[v.Validators().Project])
	profile_value=forms.CharField(required=True,validators=[v.Validators().Project])
	profile_json=forms.CharField(required=False)
