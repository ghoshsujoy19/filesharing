from django.db import models
from datetime import date
from django.contrib.auth.models import User
from django.utils.timezone import now
# Create your models here.


class Department(models.Model):
    deptName = models.CharField(max_length=100, default='')
    isActive = models.BooleanField(default=True)
    courseType = models.CharField(max_length=100, default='')
    semesterCount = models.IntegerField(default=0)


class Course(models.Model):
    dept = models.ForeignKey(Department, on_delete=models.CASCADE)
    courseID = models.CharField(max_length=20, default='', primary_key=True)
    courseName = models.CharField(max_length=100, default='')
    totalFiles = models.BigIntegerField(default=0)
    semester = models.IntegerField(default=1)
    isActive = models.BooleanField(default=True)


class PaperUpload(models.Model):
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    file = models.FileField(upload_to='papers/')
    filename = models.CharField(max_length=100, default='')
    uploadUser = models.ForeignKey(User, on_delete=models.DO_NOTHING , null=True)
    examDate = models.IntegerField(default=0)
    numLikes = models.BigIntegerField(default=0)
    numDislikes = models.BigIntegerField(default=0)
    isActive = models.BooleanField(default=True)
    reasonDislike = models.CharField(default='', max_length=1000)
    alreadyLiked = models.BooleanField(default=False)
    alreadyDisliked = models.BooleanField(default=False)
