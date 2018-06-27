from django.shortcuts import render, HttpResponseRedirect, get_object_or_404, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from .models import Department, PaperUpload, Course
from django.conf import settings
import sendgrid, random, string
from sendgrid.helpers.mail import *


# Create your views here.
def home(request):
    if request.user.is_anonymous:
        return HttpResponseRedirect('/login/')

    if not request.user.is_authenticated:
        return HttpResponseRedirect('/login/')
    depts = Department.objects.values_list('deptName', flat=True).distinct()
    department = {}
    deptser = Department.objects.all()
    for dp in deptser:
        dName = dp.deptName
        dActive = dp.isActive
        dType = dp.courseType
        if dActive is not True:
            continue
        elif dName in department:
            department[dName].append(dType)
        else:
            department[dName] = [dType,]

    # print(deptser)
    context = {'depts':depts, 'department':department}
    return render(request, 'index.html', context=context)


def activateEmail(request, pk):
    pk = int(pk)
    user = User.objects.get(pk=pk)
    if user.is_active:
        return HttpResponseRedirect('/home/')
    user.is_active = True
    user.save()
    message = {}
    return render(request, 'message.html', message)


def uploadfile(request):
    fileEnter = request.FILES.get('file-input', None)
    description = request.POST['text-input']
    examYear = request.POST['year-input']
    dept = request.POST['dept']
    ctype = request.POST['ctype']
    semester = request.POST['semester']
    course = request.POST['course']
    newfile = PaperUpload()
    newfile.file = fileEnter
    newfile.filename = description
    newfile.uploadUser = request.user
    newfile.examDate = examYear
    cp = Course.objects.get(dept__courseType=ctype, dept__deptName=dept, semester=semester, courseID=course)
    newfile.course = cp
    newfile.save()
    return HttpResponseRedirect('/home/')



def semester(request):
    dept = request.GET.get('dept')
    branch = request.GET.get('branch')
    semesters = Department.objects.get(deptName=dept,courseType=branch)
    context = {'num': semesters.semesterCount}
    return JsonResponse(context)


def listcourse(request):
    # ddc = {'CS110':'happy','CS102':'newly'}
    dept = request.GET.get('dept')
    branch = request.GET.get('branch')
    semester = request.GET.get('semester')
    semester = int(semester)
    courseList = Course.objects.filter(dept__deptName=dept, dept__courseType=branch, semester=semester)
    context = {}
    for course in courseList:
        context[course.courseID] = course.courseName
    return JsonResponse(context)

def sitelogin(request):
    if 'message' not in request.session:
        request.session['message'] = ''
    print(request.user)
    return render(request,'login.html',{'message':request.session['message']})


def sitelogout(request):
    if request.user.is_anonymous:
        return HttpResponseRedirect()
    if not request.user.is_authenticated:
        return HttpResponseRedirect('/login/')
    logout(request)
    return HttpResponseRedirect('/home/')


def goLogin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        request.session['message'] = ''
        # print(username,password)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/home/')
        request.session['message'] = 'Please verify your email or contact admin'

        return HttpResponseRedirect('/login/')
    return HttpResponseRedirect('/login/')


def siteregister(request):
    return render(request, 'register.html')


def goregister(request):
    username = request.POST['username']
    firstname = request.POST['firstname']
    lastname = request.POST['lastname']
    email = request.POST['email']
    password = request.POST['password']
    agree = request.POST['agree']
    exists = User.objects.filter(username=username).exists()
    if exists:
        return HttpResponseRedirect('/login/')
    if not agree:
        return HttpResponseRedirect('/register/')
    newUser = User()
    newUser.username = username
    newUser.set_password(password)
    newUser.email = email
    newUser.first_name = firstname
    newUser.last_name = lastname
    newUser.is_active = False
    newUser.save()
    primaryKey = newUser.pk
    apikey = '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'
    sg = sendgrid.SendGridAPIClient(apikey=apikey)
    from_email = Email("noreply@iitg.com")
    to_email = Email(email)
    subject = "Email Activation"
    content = Content("text/plain", "Please open http://127.0.0.1:8000/activate/"+str(primaryKey)+"/ to activate your account")
    mail = Mail(from_email, subject, to_email, content)
    response = sg.client.mail.send.post(request_body=mail.get())
    return HttpResponseRedirect('/login/')


def selectCourseType(request):
    dept = request.GET.get('dept', None)
    print(dept)
    cType = []
    depts = Department.objects.filter(deptName=dept)
    for dep in depts:
        cType.append(dep.courseType)
    context = {'cType':cType}
    print(context)
    return JsonResponse(context)


def selectSemester(request):
    dept = request.GET.get('dept', None)
    ctype = request.GET.get('ctype', None)
    req = Department.objects.get(deptName=dept, courseType=ctype)
    context = {'numsem' : req.semesterCount}
    return JsonResponse(context)


def selectCourse(request):
    dept = request.GET.get('dept', None)
    ctype = request.GET.get('ctype', None)
    sem = request.GET.get('sem', None)
    sem = int(sem)
    req = Course.objects.filter(dept__deptName=dept, dept__courseType=ctype, semester=sem)
    courses = {}
    for cop in req:
        courses[cop.courseID] = cop.courseName
    print(courses)
    return JsonResponse(courses)


# mainuser for loading site
def siteload(request):
    departments = Department.objects.values_list('deptName', flat=True).distinct()
    context = {'dept': departments}
    for dept in departments:
        ctype = Department.objects.values_list('courseType', flat=True)
        context[dept] = ctype
    site = 'index.html'
    return render(request, site, context=context)


# admin/mainuser - for showing all department
def showDepartments(request):
    departments = Department.objects.values_list('deptName', flat=True).distinct()
    context = {'dept' : departments}
    return JsonResponse(context)


# admin/mainuser - for showing files
def selectCourseType2(request):
    dept = request.GET.get('dept', None)
    print(dept)
    cType = []
    depts = Department.objects.filter(deptName=dept)
    for dep in depts:
        cType.append(dep.courseType)
    relFiles = showFilesFilter1(dept)
    context = {'cType':cType, 'files' : relFiles}
    print(context)
    return JsonResponse(context)


def selectSemester2(request):
    dept = request.GET.get('dept', None)
    ctype = request.GET.get('ctype', None)
    req = Department.objects.get(deptName=dept, courseType=ctype)
    relFiles = showFilesFilter2(dept, ctype)
    context = {'numsem' : req.semesterCount, 'files' : relFiles}
    return JsonResponse(context)


def selectCourse2(request):
    dept = request.GET.get('dept', None)
    ctype = request.GET.get('ctype', None)
    sem = request.GET.get('sem', None)
    sem = int(sem)
    req = Course.objects.filter(dept__deptName=dept, dept__courseType=ctype, semester=sem)
    courses = {}
    for cop in req:
        courses[cop.courseID] = cop.courseName
    relFiles = showFilesFilter3(dept, ctype, sem)
    context = {'courses' : courses, 'files' : relFiles}
    return JsonResponse(context)


def selectFiles2(request):
    dept = request.GET.get('dept', None)
    ctype = request.GET.get('ctype', None)
    sem = request.GET.get('sem', None)
    sem = int(sem)
    courseID = request.GET.get('course', None)
    relFiles = showFilesFilter4(dept, ctype, sem, courseID)
    context = {'files' : relFiles}
    return JsonResponse(context)


def selectAllFiles2(request):
    relFiles = showFiles()
    context = {'files' : relFiles}
    return JsonResponse(context)


def showFiles():
    files = PaperUpload.objects.all()
    context = {}
    for uploadFile in files:
        likes = uploadFile.numLikes
        dislikes = uploadFile.numDislikes
        primaryKey = uploadFile.pk
        course = uploadFile.course.dept.courseType + ' - ' + uploadFile.course.courseID + ' - ' + str(uploadFile.course.semester)
        context[primaryKey] = {'L': likes, 'D': dislikes, 'course': course,
                               'username': uploadFile.uploadUser.username, 'dept': uploadFile.course.dept.deptName,
                               'isAct': uploadFile.isActive}
    return context


def showFilesFilter1(dept):
    files = PaperUpload.objects.filter(course__dept__deptName=dept)
    context = {}
    for uploadFile in files:
        likes = uploadFile.numLikes
        dislikes = uploadFile.numDislikes
        primaryKey = uploadFile.pk
        course = uploadFile.course.dept.courseType + ' - ' + uploadFile.course.courseID + ' - ' + str(uploadFile.course.semester)
        context[primaryKey] = {'L': likes, 'D': dislikes, 'course': course,
                         'username': uploadFile.uploadUser.username, 'dept': uploadFile.course.dept.deptName, 'isAct' : uploadFile.isActive}
    return context


def showFilesFilter2(dept, ctype):
    files = PaperUpload.objects.filter(course__dept__deptName=dept, course__dept__courseType=ctype)
    context = {}
    for uploadFile in files:
        likes = uploadFile.numLikes
        dislikes = uploadFile.numDislikes
        primaryKey = uploadFile.pk
        course = uploadFile.course.dept.courseType + ' - ' + uploadFile.course.courseID + ' - ' + str(uploadFile.course.semester)
        context[primaryKey] = {'L': likes, 'D': dislikes, 'course': course,
                         'username': uploadFile.uploadUser.username, 'dept': uploadFile.course.dept.deptName, 'isAct' : uploadFile.isActive}
    return context


def showFilesFilter3(dept, ctype, semester):
    files = PaperUpload.objects.filter(course__dept__deptName=dept, course__dept__courseType=ctype, course__semester=semester)
    context = {}
    for uploadFile in files:
        likes = uploadFile.numLikes
        dislikes = uploadFile.numDislikes
        primaryKey = uploadFile.pk
        course = uploadFile.course.dept.courseType + ' - ' + uploadFile.course.courseID + ' - ' + str(uploadFile.course.semester)
        context[primaryKey] = {'L': likes, 'D': dislikes, 'course': course,
                         'username': uploadFile.uploadUser.username, 'dept': uploadFile.course.dept.deptName, 'isAct' : uploadFile.isActive}
    return context


def showFilesFilter4(dept, ctype, semester, courseID):
    files = PaperUpload.objects.filter(course__dept__deptName=dept, course__dept__courseType=ctype, course__semester=semester, course__courseID=courseID)
    context = {}
    for uploadFile in files:
        likes = uploadFile.numLikes
        dislikes = uploadFile.numDislikes
        primaryKey = uploadFile.pk
        course = uploadFile.course.dept.courseType + ' - ' + uploadFile.course.courseID + ' - ' + str(uploadFile.course.semester)
        context[primaryKey] = {'L': likes, 'D': dislikes, 'course': course,
                               'username': uploadFile.uploadUser.username, 'dept': uploadFile.course.dept.deptName, 'isAct' : uploadFile.isActive}
    return context


def showFilesFilternew(request):
    dept = request.GET.get('dept', None)
    ctype = request.GET.get('branch', None)
    semester = request.GET.get('semester', None)
    semester = int(semester)
    courseID = request.GET.get('courseID', None)
    files = PaperUpload.objects.filter(course__dept__deptName=dept, course__dept__courseType=ctype, course__semester=semester, course__courseID=courseID)
    context = {}
    for uploadFile in files:
        likes = uploadFile.numLikes
        dislikes = uploadFile.numDislikes
        primaryKey = uploadFile.pk
        context[primaryKey] = {'L':likes,'D':dislikes,'name':uploadFile.filename}
    return JsonResponse(context)


def downloadFile(request, primaryKey):
    primaryKey = int(primaryKey)
    reqFile = PaperUpload.objects.get(pk=primaryKey)
    xp = reqFile.pk
    print(xp)
    path = settings.MEDIA_ROOT + reqFile.file.url
    with open('.'+reqFile.file.url, 'rb') as pdf:
        response = HttpResponse(pdf.read(), content_type='application/pdf')
        response['Content-Disposition'] = 'inline;filename=xyz.pdf'
        return response
    # return HttpResponseRedirect('/home/')


# for admin html site rendering

def getsiteadmin(request, req):
    if request.user.is_anonymous:
        return HttpResponseRedirect('/login/')
    elif not request.user.is_staff:
        return HttpResponseRedirect('/login/')
    elif req == 'users':
        return render(request, 'adminUsers.html', showUsers())
    elif req == 'files':
        depts = Department.objects.values_list('deptName', flat=True).distinct()
        files = PaperUpload.objects.all()
        maincc = {'depts':depts,'files':files}
        return render(request, 'adminFiles.html',maincc)
    elif req == 'courses':
        depts = Department.objects.values_list('deptName', flat=True).distinct()
        courses = Course.objects.all()
        context = {'context' : courses,'depts':depts}
        return render(request, 'adminCourses.html', context)
    else:
        allDept = Department.objects.all()
        context = {'context' : allDept}
        return render(request, 'adminDepartment.html', context)


def addDepartment(request):
    deptName = request.POST['deptName']
    courseType = request.POST['courseType']
    semesterCount = request.POST['semesterCount']
    newDept = Department()
    newDept.semesterCount = semesterCount
    newDept.courseType = courseType
    newDept.deptName = deptName
    newDept.save()
    return HttpResponseRedirect('/siteadmin/dept/')


def addCourse(request):
    deptName = request.POST['department']
    courseType = request.POST['coursetype']
    semester = request.POST['semester']
    courseID = request.POST['courseID']
    courseName = request.POST['courseName']
    newCourse = Course()
    newCourse.dept = Department.objects.get(deptName=deptName, courseType=courseType, isActive=True)
    newCourse.semester = semester
    newCourse.courseName = courseName
    newCourse.courseID = courseID
    newCourse.save()
    return HttpResponseRedirect('/siteadmin/courses/')


def showUsers():
    users = User.objects.all()
    context = {'users':users}
    return context


def showUploads(request):
    if request.user.is_anonymous:
        return HttpResponseRedirect('/login/')
    if not request.user.is_authenticated:
        return HttpResponseRedirect('/login/')
    files = PaperUpload.objects.filter(uploadUser=request.user)
    return render(request,'useruploads.html', {'files':files})


def userLiked(request):
    pk = request.GET.get('pk', None)
    pk = int(pk)
    filereq = PaperUpload.objects.get(pk=pk)
    alreadyLiked = filereq.alreadyLiked
    alreadyDisliked = filereq.alreadyDisliked
    likes = filereq.numLikes
    dislikes = filereq.numDislikes
    context = {'L':likes,'D':dislikes}
    if alreadyLiked:
        return JsonResponse(context)
    elif alreadyDisliked:
        context['D'] = dislikes-1
        filereq.alreadyDisliked = False
        filereq.numDislikes = dislikes-1
        filereq.save()
        return JsonResponse(context)
    else:
        context['L'] = likes+1
        filereq.alreadyLiked = True
        filereq.numLikes = likes+1
        filereq.save()
        return JsonResponse(context)


def userDisliked(request):
    pk = request.GET.get('pk', None)
    pk = int(pk)
    filereq = PaperUpload.objects.get(pk=pk)
    alreadyLiked = filereq.alreadyLiked
    alreadyDisliked = filereq.alreadyDisliked
    likes = filereq.numLikes
    dislikes = filereq.numDislikes
    context = {'L':likes,'D':dislikes}
    if alreadyDisliked:
        return JsonResponse(context)
    elif alreadyLiked:
        context['L'] = likes-1
        filereq.alreadyLiked = False
        filereq.numLikes = likes-1
        filereq.save()
        return JsonResponse(context)
    else:
        context['D'] = dislikes+1
        filereq.alreadyDisliked = True
        filereq.numDislikes = dislikes+1
        filereq.save()
        return JsonResponse(context)


def forgotpass(request):
    return render(request, 'forget-pass.html')


def userCheckandPass(request):
    context = {'message':'No such account exists!!!!!!'}
    username = request.POST['username']
    email = request.POST['email']
    users = User.objects.filter(username=username, email=email).count()
    if users is None:
        return render(request, 'forgotpasserrormessage.html', context)
    elif users > 1:
        context['message'] = 'Invalid Request!!!!!!!'
        return render(request, 'forgotpasserrormessage.html', context)
    else:
        user = User.objects.get(username=username, email=email)
        context['message'] = 'Your new password has been sent to your mailid; it may be in spam folder. Please change that password for your own safety!!'
        randStr = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        user.set_password(randStr)
        user.save()
        apikey = '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'
        sg = sendgrid.SendGridAPIClient(apikey=apikey)
        from_email = Email("noreply@iitg.com")
        to_email = Email(email)
        subject = "Pass Req"
        content = Content("text/plain", randStr)
        mail = Mail(from_email, subject, to_email, content)
        response = sg.client.mail.send.post(request_body=mail.get())

        return render(request, 'forgotpasserrormessage.html', context)


def changepass(request):
    if request.user.is_anonymous:
        return HttpResponseRedirect('/login/')
    if not request.user.is_authenticated:
        return HttpResponseRedirect('/login/')
    return render(request, 'changepass.html')

# 4748412
def userChangepass(request):
    oldpass = request.POST['oldpass']
    newpass = request.POST['newpass']
    newpassconf = request.POST['newpassconf']
    if newpass != newpassconf:
        return HttpResponseRedirect('/changepass/')
    user = User.objects.get(pk=request.user.pk)
    val = user.check_password(oldpass)
    print(val)
    if val:
        logout(request)
        user.set_password(newpass)
        user.save()
        login(request, user)
        return HttpResponseRedirect('/home/')
    else:
        return HttpResponseRedirect('/changepass/')

