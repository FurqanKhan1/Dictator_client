# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-05-20 09:51
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('log', '0003_auto_20170216_1508'),
        ('Dictator', '0002_auto_20170117_0726'),
    ]

    operations = [
        migrations.CreateModel(
            name='Profiles',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_id', models.TextField(blank=True, max_length=500)),
                ('assessment_id', models.TextField(max_length=100)),
                ('created_time', models.DateField(default=datetime.date.today, verbose_name='Date')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='log.Profile')),
            ],
        ),
    ]
