# Generated by Django 2.0.5 on 2018-06-23 18:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mainbase', '0006_auto_20180623_1747'),
    ]

    operations = [
        migrations.AddField(
            model_name='paperupload',
            name='alreadyDisliked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='paperupload',
            name='alreadyLiked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='paperupload',
            name='reasonDislike',
            field=models.CharField(default='', max_length=1000),
        ),
    ]