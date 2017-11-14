# Virtualenv

### Annoying and common Python problems
* > I want to run these two Django web apps, but they both use a different version of Django
* > I use Linux and I'm sick of typing my password in for every `pip install`
* > I don't want to install heaps of junk packages for every random tool I want to use and clutter up my system

### How can we fix them
`virtualenv` - [docs](https://virtualenv.pypa.io/en/stable/)

This module lets you create a new clean Python environment for each project

### Side note on Python projects
Most (basically all) Python projects will have a file `requirements.txt`.

This will list all pip packages required to run the project. e.g. 
```python
# requirements.txt
Flask==0.12.2
Jinja2==2.9.6
requests==2.18.4
urllib3==1.22
```
to install these packages, you would run
```sh
pip install -r requirements.txt
```

### How do I get started
Installation:
```sh
pip install virtualenv
```

Create a virtual environment:
```sh
virtualenv venv
```
(_note: `--no-site-packages` is deprecated_)

Now activate the environment:
```sh
source venv/bin/activate
```
Now you'll see the name of the current virtualenv in your terminal

### Let's see what we can do
```sh
which python	# <working_dir>/venv/bin/python
which pip	# <working_dir>/venv/bin/pip>
pip list	# nothing

# install some packages
pip install flask==0.10.0
pip install nose
pip freeze	# look at the installed packages

# check to see if nosetests is on our path
nosetests
echo $PATH	# should include venv/bin
ls venv/bin/	# python2.7 pip2.7 nosetests
```
now let's switch environment
```sh
deactivate
virtualenv venv2
source venv2/bin/activate

# let's do things differently
pip install flask==0.12.2
```


### Python3
For Python >3.6, module [venv](https://docs.python.org/3/library/venv.html#module-venv) is built in
```sh
python3 -m venv new-venv

# let's see how this one looks
source new-venv/bin/activate
python --version
pip --version	# pip and python symlinked to py3
ls new-venv/bin
```
Works the same as virtualenv for Python 2 :)