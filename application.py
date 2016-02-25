from __future__ import nested_scopes, generators, division, absolute_import, with_statement, print_function, unicode_literals
import flask, shutil, smtplib, database_setup, random, string, datetime, httplib2, json, math, requests, os, inspect, calendar, urllib, hashlib, time
from flask import Flask, Response, render_template, request, redirect, json, jsonify, url_for, flash, make_response, send_from_directory, abort, escape, g, send_file
application = Flask(__name__)
from werkzeug import secure_filename

from sqlalchemy import create_engine, asc, and_, or_, func, desc, exists
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Properties, Users, Category
from flask import session as login_session

from random import randint
from jinja2 import Environment, FileSystemLoader
from decimal import Decimal

# import flask session as the login_session for logging in
from flask import session as login_session

# Import OAuth2
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']


# Create Database Session
engine = create_engine('sqlite:///database.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# CREATES A RANDOM SECRET KEY
Flask.secret_key = '\x15\x03\xf2\xacs\xd5\x84\xe4\xe5\n.Vc\xe7\xa3\x9d\x8c\xe3\x079\xb2\x9c\xab1'


# Home
@application.route('/')
@application.route('/index/')
@application.route('/index/<category>/')
# If no category preference is selected, default to 'All'
def showHome(category = 'All'):
	getUserData()

	# Determine which category the viewer wants to see
	if category == 'All':
		# Get all of the properties from the database
		properties = session.query(Properties).all()
		cat = None
	else:
		# Get just the properties with a rent type that match the category
		properties = session.query(Properties).filter_by(pRentType = category).all()
		try:
			cat = session.query(Category).filter_by(cRentType = category).one()
		except:
			cat = None

	# Display the template
	return render_template('home.html', properties = properties, cat = cat)


# Login
@application.route('/login/', methods=['GET', 'POST'])
def login():
	getUserData()
	# Create a state variable that is a mix of uppercase letters and digits
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	# Store 'state' in the login_session object under the name 'state'
	login_session['state'] = state
	return render_template('login.html', STATE = state)

# Process Google Login
@application.route('/gconnect', methods=['GET', 'POST'])
def gconnect():
	print('start gconnect')
	# Validate state token
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Obtain authorization code
	code = request.data

	try:
		# Upgrade the authorization code into a credentials object
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Check that the access token is valid.
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
	# If there was an error in the access token info, abort.
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'

	# Verify that the access token is used for the intended user.
	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
		response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Verify that the access token is valid for this app.
	print('Verify that the access token is valid for this app.')
	if result['issued_to'] != CLIENT_ID:
		print("if result['issued_to'] != CLIENT_ID:")
		response = make_response(json.dumps("Token's client ID does not match app's."), 401)
		print("Token's client ID does not match app's.")
		response.headers['Content-Type'] = 'application/json'
		return response

	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	print('stored credentials')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
		print("if stored_credentials is not None and gplus_id == stored_gplus_id:")
		response = make_response(json.dumps('Current user is already connected.'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Store the access token in the session for later use.
	print('Store the access token in the session for later use.')
	login_session['credentials'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	# Get user info
	print('Get user info')
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']

	# Add the user to our database if they have not already been added
	print('try adding user')
	try:
		user = session.query(Users).filter_by(email = login_session['email']).one()
		print('user already created')
	except:
		print('creating new user')
		user = Users(
			email = login_session['email'], 
			picture = login_session['picture'],
			name = login_session['username']
		)
		try:
			session.add(user)
			session.commit()
		except:
			session.rollback()
			raise
		print('new user created')

	print('CLIENT_ID = %s' % CLIENT_ID)

	return redirect(url_for('addProperty'))

# Disconnect a user's token and reset their login_session
@application.route('/logout')
def logout():
	try:
		credentials = login_session['credentials']
	# Only disconnect a connected user
	except:
		response = make_response(json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Execute HTTP GET request to revoke current token
	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['credentials']
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]
	if result['status'] == '200':
		del login_session['credentials'] 
		del login_session['gplus_id']
		del login_session['username']
		del login_session['email']
		del login_session['picture']
		return redirect(url_for('showHome'))
	else:
		response = make_response(json.dumps('Failed to revoke token for given user.', 400))
		response.headers['Content-Type'] = 'application/json'
		return response

		
# Add Property
@application.route('/property/add/', methods = ['GET','POST'])
def addProperty():
	# Redirect the user to login, if they are not logged in
	if not userLoggedIn():
		return redirect(url_for('login'))

	# Add the Property to the database
	if request.method == 'POST':
		submission = Properties(
			userEmail = g.current_user.email,
			pCity = request.form['city'],
			pState = request.form['state'],
			pTitle = request.form['title'],
			pDescription = request.form['description'],
			pAcres = request.form['acres'],
			pPrice = request.form['price'],
			pRentType = request.form['rentType'],
		)
		try:
			session.add(submission)
			session.commit()
		except:
			session.rollback()
			raise
		
		# Redirect to home page when complete
		return redirect(url_for('showHome'))
	else:
		return render_template('addProperty.html')


# Edit Property
@application.route('/property/<int:pID>/edit/', methods = ['GET','POST'])
#@fresh_login_required
def editProperty(pID):
	# Redirect the user to login, if they are not logged in
	if not userLoggedIn():
		return redirect(url_for('login'))
	try:
		editedProperty = session.query(Properties).filter_by(pID = pID).one()
	except:
		return redirect(url_for('addProperty'))
	# Redirect the user to login if they are not the owner of the property
	if editedProperty.userEmail != login_session['email']:
		return redirect(url_for('login'))

	if request.method == 'POST':
		if request.form['city'] != editedProperty.pCity:
			editedProperty.pCity = request.form['city']
		if request.form['state'] != editedProperty.pState:
			editedProperty.pState = request.form['state']
		if request.form['title'] != editedProperty.pTitle:
			editedProperty.pTitle = request.form['title']
		if request.form['description'] != editedProperty.pDescription:
			editedProperty.pDescription = request.form['description']
		if request.form['acres'] != editedProperty.pAcres:
			editedProperty.pAcres = request.form['acres']
		if request.form['price'] != editedProperty.pPrice:
			editedProperty.pPrice = request.form['price']
		if request.form['rentType'] != editedProperty.pRentType:
			editedProperty.pRentType = request.form['rentType']
		try:
			session.add(editedProperty)
			session.commit()
		except:
			session.rollback()
			raise
		return redirect(url_for('showHome'))
	else:
		return render_template('editProperty.html', p = editedProperty)

# Delete Property
@application.route('/property/<int:pID>/delete/', methods = ['GET','POST'])
#@fresh_login_required
def deleteProperty(pID):
	# Redirect the user to login, if they are not logged in
	if not userLoggedIn():
		return redirect(url_for('login'))
	try:
		deletedProperty = session.query(Properties).filter_by(pID = pID).one()
	except:
		return redirect(url_for('addProperty'))
	# Redirect the user to login if they are not the owner of the property
	if deletedProperty.userEmail != login_session['email']:
		return redirect(url_for('login'))

	if request.method == 'POST':
		try:
			session.delete(deletedProperty)
			session.commit()
		except:
			session.rollback()
			raise
		return redirect(url_for('showHome'))
	else:
		return render_template('deleteProperty.html', p = deletedProperty)

# View Property
@application.route('/property/<int:pID>/')
def viewProperty(pID):
	getUserData()
	prop = session.query(Properties).filter_by(pID=pID).one()
	return render_template('viewProperty.html', p = prop)



############################################################################################################################
#
#                                                        JSON
#
############################################################################################################################

# Resturn JSON for individual property
@application.route('/property/<int:pID>/JSON')
def propertyJSON(pID):
	prop = session.query(Properties).filter_by(pID = pID).one()
	return jsonify(Property=prop.serialize)

# Resturn JSON for all properties
@application.route('/JSON')
def allPropertyJSON():
	properties = session.query(Properties).all()
	return jsonify(Properties=[p.serialize for p in properties])


############################################################################################################################
#
#                                                       FUNCTIONS
#
############################################################################################################################

# Saves the user data to a global variable that can be used in every page where this function is called
#   This function is not necessary on pages that the user must be logged in to access
def getUserData():
	try:
		user = session.query(Users).filter_by(email = login_session['email']).one()
		g.current_user = user
	except:
		g.current_user = None
	return

# Verifies the user is logged in, and redirects them if they are not
def userLoggedIn():
	getUserData()
	print('g.current_user = %s' % g.current_user)
	if g.current_user is None:
		print('redirect')
		return False
	else:
		return True

## Populate Database
#@application.route('/populateDatabase/')
#def populateDatabase():
#	propertyTitles = ['Big Open Land', 'Great Hunting Area', 'Awesome Deer Hunting', 'Lots of Land', 'Hilltop retreat', 'Right Near the Lake']
#	cities = ['DeKalb', 'Springfield', 'Mokena', 'Denton', 'Valley Ridge']
#	states = ['IL', 'TX', 'CA', 'MO', 'WI']
#	rentTypes = ['Private', 'Public', 'Guided', 'SemiGuided', 'Lease']
#	for title in propertyTitles:
#		submission = Properties(
#			userEmail = 'mark@landtohunt.com',
#			pCity = cities[randint(0,4)],
#			pState = states[randint(0,4)],
#			pTitle = title,
#			pDescription = populateDescription(),
#			pAcres = randint(20,10000),
#			pPrice = randint(50,2000),
#			pRentType = rentTypes[randint(0,4)],
#		)
#		try:
#			session.add(submission)
#			session.commit()
#		except:
#			session.rollback()
#			raise

#	categoryDescriptions = {'Private':'This land is owned by an individual who is willing to let you use the property for a day or week for a fee. You will not have to share this property with any other hunters, unless you invite them into your hunting party.', 'Public':'This land is owned by a government entity (US Governement, State, County, etc.) for hunting use by the general public. Each state has different rules regarding access to these properties.', 'Guided':'Guides provide you with lodging, food (breakfast/lunch/dinner), and join you on the hunt to help you track and determine the best places to go for hunting. They also help you clean the harvested game, and transport you and the game back to camp.', 'SemiGuided':'Some properties are semi-guided, providing only food (breakfast/lunch/dinner), lodging and transportation to the hunting lands. You must track and clean your own game.', 'Lease':'Leases are paid annually, and are typically good for the entire hunting season (Fall through Spring), although some leases may be shorter or longer depending on what you work out with the landowner.'}
#	for type in rentTypes:
#		cat = Category(
#			cRentType = type,
#			cDescription = categoryDescriptions[type]
#		)
#		try:
#			session.add(cat)
#			session.commit()
#		except:
#			session.rollback()
#			raise

#	return redirect(url_for('showHome'))

## Creates Random Descriptions for Properties
#def populateDescription():
#	descriptions = ['Seen lots of deer over the weekend. ', 'Most of the timber cut in 2015, with replanting in 2016. ', 'It borders heavily wooded land. ', 'Has 1 large pond well-stocked with bream, bass and catfish. ', 'Deer, hogs, coons, yotes and dove are common. ', 'DO NOT drive through fields. OK to drive around edges, if you have 4x4 or a 4 wheeler.', 'Dont block driveway to house or pond. ', 'LOTS of deer on regular basis, especially when it is dry. ', 'Working farm, near state park. ', 'Pond has gators once in a while. If you have gator permit, have at it. ', 'This tract is loaded with turkey. ']
#	numSentences = randint(1,6)
#	desc = ''
#	i = 1
#	while(i <= numSentences):
#		desc += descriptions[randint(0,10)]
#		i += 1
#	return desc



if __name__ == "__main__":
	application.debug = True
	application.run(host='0.0.0.0')