from django.urls import path
from . import views

app_name = 'mainbase'

urlpatterns = [
    path('home/', views.home, name='home'),
    path('uploadfile/', views.uploadfile, name='uploads'),
    path('activate/<str:pk>/', views.activateEmail, name='activate'),
    path('login/', views.sitelogin, name='gologin'),
    path('logout/', views.sitelogout, name='gologout'),
    path('gologin/', views.goLogin, name='login'),
    path('register/', views.siteregister, name='gologin'),
    path('goregister/', views.goregister, name='login'),
    path('selcType/', views.selectCourseType, name='selcType'),
    path('selcsem/', views.selectSemester, name='selcsem'),
    path('selcourse/', views.selectCourse, name='selcourse'),
    path('selcType2/', views.selectCourseType2, name='selcType2'),
    path('selcsem2/', views.selectSemester2, name='selcsem2'),
    path('selcourse2/', views.selectCourse2, name='selcourse2'),
    path('selcfiles2/', views.selectFiles2, name='selcfiles2'),
    path('selcallfiles2/', views.selectAllFiles2, name='selcallfiles2'),
    path('semester/', views.semester, name='sem'),
    path('listcourse/', views.listcourse, name='cc'),
    path('showfiles/', views.showFilesFilternew, name='ccfiles'),
    path('download/<str:primaryKey>/', views.downloadFile, name='download'),
    path('siteadmin/<str:req>/', views.getsiteadmin, name='siteadmin'),
    path('addDept/', views.addDepartment, name='addDept'),
    path('addCourse/', views.addCourse, name='addCourse'),
    path('myuploads/', views.showUploads, name='myuploads'),
    path('addlikes/', views.userLiked, name='addlike'),
    path('addislikes/', views.userDisliked, name='addislike'),
    path('forgotpass/', views.forgotpass, name='forgotpass'),
    path('goforgotpass/', views.userCheckandPass, name='goforgotpass'),
    path('changepass/', views.changepass, name='changepass'),
    path('gochangepass/', views.userChangepass, name='gochangepass'),
]