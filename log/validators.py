from __future__ import unicode_literals
from django.core.validators import RegexValidator


class Validators:
	"""
	Objective :
	This class has various regular expressions and is used for whitelisting the obtained input
	"""

	def __init__(self):
		"""
		Objective :
		This method actually is the constructor and it initialises varioys regular expressions that will
		be used against data to be validated
		"""

		self.IP=RegexValidator(r'^[0-9a-zA-Z.,/-]*$','The given IP address /Range is in invalid format')
		self.decimal=RegexValidator(r'^[0-9]*$','Invalid value')
		self.Port=RegexValidator(r'^[0-9a-zA-Z_-]*$','Invalid value')
		self.alpha_num=RegexValidator(r'^[0-9A-Za-z]*$','Invalid value')
		self.Project=RegexValidator(r'^[0-9A-Za-z_]*$','Invalid value ,only special character allowed is "_"')
		self.alpha_num_sp=RegexValidator(r'^[0-9A-Za-z_?.-]*$','Invalid value.Only special character allowed is "_" , "?", "-","_",":"')
		self.alpha_only=RegexValidator(r'^[a-zA-Z]*$','Invalid Value Supplied')

