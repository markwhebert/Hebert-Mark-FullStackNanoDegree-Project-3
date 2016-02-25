# Udacity Full Stack Web Developer Nanodegree
# Project 3 - Catalog
Author: Mark Hebert


# Background
------------
This website is based on a similar website I built (http://LandToHunt.com). 
For simplicity sake, many of the features available on LandToHunt have been removed.


# Directions
------------
These directions assume you already have VirtualBox and Vagrant properly
 installed on your computer.  If you do not, VirtualBox can be downloaded 
 from https://www.virtualbox.org/wiki/Downloads and Vagrant can be 
 downloaded from https://www.vagrantup.com/downloads

Accessing Vagrant:
------------------
 Using the terminal, change the directory to the location of the file
   (example: $ cd /c/Users/udacity/Desktop/fullstack/vagrant/)
 Then type "vagrant up" to launch the virtual machine
 Once it is running, type "vagrant ssh" to log into it.
 When you want to log out, type "exit".
 To turn off the virtual maching (without deleting anything), type
   "vagrant halt".  If you do this, you will need to run "vagrant up" 
   again before you can log into it.

Running the Program:
--------------------
 After navigating to the folder that contains the application ("cd catalog"), 
type "python application.py", from the command line. 

Accessing the Website:
----------------------
Once the application is running, enter the following address in your browser 
"http://localhost:5000"


# Using the Website
-------------------
Viewing Properties:
-------------------
From the home page, you can see every property in the database. You can refine the 
results by category in the left column. Click on the property to view its details.

Logging In:
-----------
You must have a Google account to login. Use the button at the top right to login.

Logging Out:
------------
Logging out is similar to logging in. Use the button at the top right to log out.

Adding Properties:
------------------
Once you have logged in, a button in the top right of the page (Add Property) will 
appear. Click this button to add your property.

Edit and Delete Properties:
---------------------------
When you are logged int, buttons labeled 'Edit' and 'Delete' will appear below the 
properties you have created. You can only edit or delete propeties you have created.


# Resources
-----------
Udacity - Intro to Relational Databases
https://www.udacity.com/courses/ud330

Python Documentation
https://docs.python.org/3.4/index.html

StackOverflow
http://stackoverflow.com/

LandToHunt.com
http://LandToHunt.com/