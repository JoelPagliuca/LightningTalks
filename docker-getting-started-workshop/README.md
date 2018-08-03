# Docker getting-started workshop

## Prep
Get `docker` + `docker-compose` on your machine

Either:
* Download this [minimal Linux VM](http://dl.bintray.com/vmware/photon/2.0/GA/ova/photon-custom-lsilogic-hw11-2.0-304b817.ova) that includes Docker
	* make sure you can copy stuff to this VM
* Download and install from [Docker website](https://docs.docker.com/docker-for-mac/install/)

* * *

## Intro
* Images vs Containers - [docs](https://docs.docker.com/v17.09/engine/userguide/storagedriver/imagesandcontainers/#images-and-layers)
![Images and Containers](./container-layers.jpg)
* `docker run -it alpine:3.7`
```sh
$ whoami
# root
$ uname -a
# Linux ...
$ cat /etc/alpine-release
# 3.6.2
$ exit
```

## 1 - Static html server

Let's serve a [html](1-static-html/test.html) file. (`cd 1-static-html`)

* There's an Nginx image [available](https://hub.docker.com/_/nginx/)
	* The Dockerhub page usually includes downloading and running instructions
* Download it using:
	* `docker pull nginx`
* See it on your machine:
	* `docker images`
* Run it:
	* `docker run -d --rm -p 7070:80 nginx`

What happened here?

* `docker run nginx`
	* create a container based on the `nginx` image and run it
	* if `nginx` is not on the machine it will be downloaded
* `-d`
	* background
	* use `-it` to run with interactive output
* `--rm`
	* remove container after we stop it
	* otherwise it clutters up your machine a bit
* `-p 7070:80`
	* map the host port *7070* to the container port *80*

More commands

* `docker ps`
	* check status of your containers
	* `-a` will give you all the stopped containers as well
* `docker stop <container_id/name>`
	* stop a container
* `docker rm <container_id/name>`
	* remove container
* `docker rmi <image_id/name>`
	* remove image

# 2 - Django app

Lets build a container for the Django app in `./2-django/`

* Make a Dockerfile in that directory
* Common directives
	* `FROM <base_image>`
		* chose a starting point
	* `ADD <host_directory> <container_directory>`
		* add files from the host to the container
	* `RUN <command>`
		* run a command within the image
	* `CMD ["cmd", "arg"]`
		* set the instruction that's run when you do `docker run`
* What we need for our Docker image
	* A [base image](https://hub.docker.com/_/python/)
		* `FROM python:alpine3.7`
	* The Django code from that directory
		* `ADD ./mysite /app`
	* Django itself
		* `RUN pip install django`
	* The instructions to run the server
		* `CMD ["python", "/app/manage.py", "runserver", "0.0.0.0:8080"]`
* Now build our image
	* `docker build -t django-test-workshop .`
	* `-t` names the image
	* `.` gives the path to build from
* Let's run a container with our image
	* `docker run -it -p 8080:8080 django-test-workshop`
* Visit [127.0.0.1:8080/demo](http://127.0.0.1:8080/demo)

# 3 - Something with Compose

* Compose is basically a wrapper for extra docker functionality
* Really good for multiple container setups
* [docker-compose.yml](./3-compose/docker-compose.yml)

# 4 - Tools