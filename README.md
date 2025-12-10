### the world's cutest fanfic site!

to build this you will need a few things, but flask and python3 are most prevelant.
if on windows, install pip manually.
if on linux, do sudo install pip

``pip install python3 flask``

then you will need to clone the directory e.g

``git clone https://github.com/marcheesed/kawfee-main``

that will give you the code!

you will then cd into the directory it outputted in, and do

``python setup.py
python test.py``

or 

``python3 setup.py
python3 test.py``

theyre the same command.

setup.py will create a new database, and test.py will create an admin user for that database.
the password is in the file, though you are expected to change it and the username in production for obvious reasons.

once ran, the database will be setup. make sure the line in app.py matches with the name you gave the database file,
before doing:

``python app.py`` or ``python3 app.py``. it'll give you a flask debugging mode, you should then do CTRL + clicking on the link provided (your ip + a 5000 port) to get to the site! 
it will be completely empty, and you will have to make the content within. you can register more accounts using invite codes.
