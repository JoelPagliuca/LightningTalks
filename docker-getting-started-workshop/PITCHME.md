# Docker getting-started workshop

---

## @fa[laptop] Prep
Get @color[#0DB7ED](`docker`) +  @color[#0DB7ED](`docker-compose`) on your machine

* Download this [minimal Linux VM](http://dl.bintray.com/vmware/photon/2.0/GA/ova/photon-custom-lsilogic-hw11-2.0-304b817.ova) that includes Docker
	* make sure you can copy stuff to this VM
OR
* Download and install from [Docker website](https://docs.docker.com/docker-for-mac/install/)

Clone [this](https://github.com/joelpagliuca/lightningtalks) repo for the content

---

@snap[midpoint]
@size[4em](VALUE)
@snapend

Note: Debug, Annecdotes, Direction, Plant the seed, mistakes

---

## @fa[book] What we are actually doing

@ul
* @fa[code] Run a container
* @fa[code] Static html server
* @fa[code] Django app
* @fa[code] Multi-container setup
* @fa[code] Play with prebuilt stuff
@ulend

---

## @fa[rocket] Intro
Images vs Containers - [docs](https://docs.docker.com/v17.09/engine/userguide/storagedriver/imagesandcontainers/#images-and-layers)

![Images and Containers](docker-getting-started-workshop/assets/images/container-layers.jpg)

Note: aufs - a union file system

---

### @fa[play-circle](`docker run -it alpine:3.7`)

Let's play with a @color[#0DB7ED](docker) container.

```sh
whoami
uname -a
cat /etc/alpine-release
exit
```

Note: alpine is the repository/image, 3.7 is the tag

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

Note: run the do.sh for custom landing page

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

Note: talk about Vagrant setup

+++

### @fa[file] The Dockerfile

Common directives

@ul
* `FROM <starting_image>` @note[choose a starting point]
* `ADD <host_directory> <container_directory>` @note[add files from the host to the container]
* `RUN <command>` @note[run a command within the image]
* `CMD ["cmd", "arg"]` @note[set the instruction that's run when you do `docker run`]
@ulend

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

+++?code=docker-getting-started-workshop/2-django/Dockerfile.bkp&lang=bash&title=Dockerfile

@[1](python alpine is pretty lightweight)
@[2](copy the files into the container)
@[3](install Python-django)
@[4](run the server)

Note: ADD preffered over COPY because ADD can be a URL

---

### @fa[code](`docker build`)

* `docker build -t django-test-workshop .`
	* `-t` names the image
	* `.` gives the path to build from
* Let's run a container with our image
	* `docker run -it -p 8080:8080 django-test-workshop`
* Visit [127.0.0.1:8080/demo](http://127.0.0.1:8080/demo)

---

## @fa[wrench] Docker-compose

@ul

* Basically a docker wrapper
* Good for multi-container setups
* Reads in a file `docker-compose.yml`

@ulend

---

### @fa[code] Run the client-server containers

* There's a compose example in `3-compose`
* `cd` in and run `docker-compose up`
* Look at the output

+++

### @fa[search-plus] What happened here?

```
Creating compose-demo-server ... done
Creating compose-demo-client ... done
Attaching to compose-demo-server, compose-demo-client
compose-demo-server | Listening on [0.0.0.0] (family 0, port 8080)
compose-demo-client | Sending message to server
compose-demo-server | Connection from 172.18.0.3 36542 received!
compose-demo-server | Message from client
compose-demo-client | Sending message to server
compose-demo-server | Connection from 172.18.0.3 36544 received!
compose-demo-server | Message from client
Killing compose-demo-client  ... done
Killing compose-demo-server  ... done
```

@[5,8](client logs)
@[4,6-7,9-10](server logs)

---?code=docker-getting-started-workshop/3-compose/docker-compose.yml&lang=yaml&title=docker-compose.yml

@[1]
@[3,23]
@[3-21](containers)
@[23-25](internal network)
@[4-13]
@[14-21]
@[5]
@[6]
@[7]
@[8-11]
@[12-13]
@[14,17,21]

Note: get them to open the file up as well

---

## @fa[wrench] Dockerized tools

* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
* [Jenkins](https://wiki.jenkins.io/display/JENKINS/Installing+Jenkins+with+Docker)
* [Nmap](https://hub.docker.com/r/frapsoft/nmap/)
* [Red-docker](https://github.com/nov3mb3r/red-docker)
* [httpd](https://hub.docker.com/_/httpd/)

---

## @fa[code] Run some prebuilt stuff

* `docker run frapsoft/nmap`
* `docker run -dit -p 8080:80 -v "<a_directory>:/usr/local/apache2/htdocs/ httpd:2.4`
	* `-v` map a directory from your host to the container
	* THIS WILL SERVER THE DIRECTORY OVER HTTP

Note: I trust these images

---

## @fa[search-plus] Where to go from here?

@ul
* networking
* volumes
* build web apps
* distribute malware
* run other people's tools
@ulend