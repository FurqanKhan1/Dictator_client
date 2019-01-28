from __future__ import unicode_literals

from django.db import models
from log import validators
#from log import models.Profile as Pr
from log.models import Profile
import datetime
from django.utils.translation import ugettext as _
#import Dictator_client.log.validators

class Projects(models.Model):
	user = models.ForeignKey('log.Profile',on_delete=models.CASCADE)
	project_id = models.TextField(max_length=500, blank=True)
	assessment_id = models.TextField(max_length=100, blank=False)
	last_start_time=models.DateField(_("Date"),default=datetime.date.today)
	
	def __unicode__(self):
		return self.project_id


class Profiles(models.Model):
	user = models.ForeignKey('log.Profile',on_delete=models.CASCADE)
	profile_id = models.TextField(max_length=500, blank=True)
	assessment_id = models.TextField(max_length=100, blank=False)
	created_time=models.DateField(_("Date"),default=datetime.date.today)
	profile_catagory=models.TextField(max_length=500,blank=True)
	
	def __unicode__(self):
		return self.profile_id


