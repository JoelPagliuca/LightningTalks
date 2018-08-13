# Docker getting-started workshop

---

## @fa[laptop] Prep
Get @color[#0DB7ED](`docker`) +  @color[#0DB7ED](`docker-compose`) on your machine

* Download this [minimal Linux VM](http://dl.bintray.com/vmware/photon/2.0/GA/ova/photon-custom-lsilogic-hw11-2.0-304b817.ova) that includes Docker
	* make sure you can copy stuff to this VM
OR
* Download and install from [Docker website](https://docs.docker.com/docker-for-mac/install/)

Note:

- aufs - a union file system

---

## @fa[rocket] Intro
Images vs Containers - [docs](https://docs.docker.com/v17.09/engine/userguide/storagedriver/imagesandcontainers/#images-and-layers)

![Images and Containers](docker-getting-started-workshop/assets/images/container-layers.jpg)

---

### @fa[play-circle](`docker run -it alpine:3.7`)

Let's play with a @color[#0DB7ED](docker) container.

```sh
$ whoami
$ uname -a
$ cat /etc/alpine-release
$ exit
```

```sh
> root
> Linux ...
> 3.6.2
# your terminal
```

Note:

- alpine is the repository/image
- 3.7 is the tag

---

## @fa[code] Static html server

Let's serve a html file @fa[arrow-right] `cd 1-static-html`

@ol
* There's an Nginx image [available](https://hub.docker.com/_/nginx/) @note[The Dockerhub page usually includes downloading and running instructions]
* Download it using:
	* `docker pull nginx`
* See it on your machine:
	* `docker images`
* Run it:
	* `docker run -d --rm -p 7070:80 nginx` @note[or do.sh]
@olend

Note:

- run the do.sh for custom landing page

---

### @fa[search-plus] What happened here?

@ul
* `docker run nginx`
	* create a container based on the `nginx` image and run it @note[if `nginx` is not on the machine it will be downloaded]
* `-d`
	* background
	* use `-it` to run with interactive output
* `--rm`
	* remove container after we stop it @note[otherwise it clutters up your machine a bit]
* `-p 7070:80`
	* map the host port *7070* to the container port *80*
@ulend

---

### @fa[info-circle] More commands

@ul
* `docker ps`
	* check status of your containers
	* `-a` will give you all the stopped containers as well
* `docker stop <container_id/name>`
	* stop a container
* `docker rm <container_id/name>`
	* remove container
* `docker rmi <image_id/name>`
	* remove image
@ulend

---

## @fa[code] Django app

Let's build a container for the Django app in 

`./2-django/`

We'll need a @color[#0DB7ED](Dockerfile) @fa[trademark]

+++

### @fa[file] The Dockerfile

Common directives

* `FROM <starting_image>`
* `ADD <host_directory> <container_directory>`
* `RUN <command>`
* `CMD ["cmd", "arg"]`

Note:

* choose a starting point
* add files from the host to the container
* run a command within the image
* set the instruction that's run when you do `docker run`
* in exec form

---

### @fa[file] The Dockerfile

@ul

* These directives provision a server for you
* Our server needs:
	* Python3
	* The code (`mysite`)
	* Django (`pip install django`)

@ulend

---

### @fa[code] The Dockerfile

@ol

* Make a Dockerfile in `2-django`
* What we need for our image
	* A [base image](https://hub.docker.com/_/python/)
	* The Django code from `mysite`
	* Django itself
	* The command to run the server

@olend

+++?code=docker-getting-started-workshop/2-django/Dockerfile.bkp&lang=dockerfile&title=Dockerfile

@[1](python alpine is pretty lightweight)

@[2](copy the files into the container, preferred over COPY because you can use a URL)

@[3](install Python-django)

@[4](run the server)

---

### @fa[wrench](`docker build`)

* `docker build -t django-test-workshop .`
	* `-t` names the image
	* `.` gives the path to build from
* Let's run a container with our image
	* `docker run -it -p 8080:8080 django-test-workshop`
* Visit [127.0.0.1:8080/demo](http://127.0.0.1:8080/demo)
