__author__ = 'furqan'

'''
Dummy configuration, so change it with your own
'''
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = '<email>'
SERVER_EMAIL = '<email>'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = '<email>'
EMAIL_HOST_PASSWORD = '<password>'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
