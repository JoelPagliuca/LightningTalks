from django.http import HttpResponse

def demo(request):
	return HttpResponse("This is the Django demo within the container")