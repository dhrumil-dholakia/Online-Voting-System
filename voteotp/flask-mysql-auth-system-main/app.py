
from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from flask import request
import pyotp
from flask_mail import *


app = Flask(__name__)


# Define a function to handle messages globally
@app.context_processor
def inject_messages():
    if 'messages' in session:
        messages = session['messages']
        session.pop('messages')  # Clear messages from session after injecting into template
        return {'messages': messages}
    return {}  # Return an empty dictionary if there are no messages



#conffigure flask mail
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']=465
app.config['MAIL_USERNAME']="samarth123xie@gmail.com"
app.config['MAIL_PASSWORD']="gxnv cnrg ljyc xrae"
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True

mail = Mail(app)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'project'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class PollForm(FlaskForm):
    option = SelectField("Select an option", choices=[], validators=[DataRequired()])
    submit = SubmitField("Vote")




# Generate a random secret key for OTP
otp_secret = pyotp.random_base32()

# Create a TOTP object
totp = pyotp.TOTP(otp_secret)


@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Generate OTP
        otp = totp.now()

        # Store OTP in session for verification
        session['otp'] = otp
        session['name'] = name
        session['email'] = email
        session['password'] = password

        # Send OTP via email
        send_otp_email(email, otp)

        # Redirect to OTP verification page
        return redirect(url_for('verify_otp'))

    return render_template('register.html', form=form)


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session:
        flash("Please register first.")
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session['otp']:
            # OTP verification successful, register user
            name = session['name']
            email = session['email']
            password = session['password']

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Store data into database 
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
            mysql.connection.commit()
            cursor.close()

            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        else:
            flash("OTP verification failed. Please try again.")

    return render_template('verify_otp.html')

def send_otp_email(email, otp):
    msg = Message('OTP for Registration', sender='your_email@gmail.com', recipients=[email])
    msg.body = f'Your OTP for registration is: {otp}'
    mail.send(msg)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            session['email'] = email  # Set email in session
            flash("Login successful.")
            return redirect(url_for('polls'))
        else:
            flash("Login failed. Please check your email and password")

    return render_template('login.html', form=form)




@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))





@app.route('/polls')
def polls():
    if 'user_id' not in session:
        flash("Please log in to access the polls.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT poll_id, question FROM polls")
    polls = cursor.fetchall()
    cursor.close()
    
    return render_template('polls.html', polls=polls)







@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
def poll(poll_id):
    if 'user_id' not in session:
        flash("Please log in to access the poll.")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM polls WHERE poll_id = %s", (poll_id,))
    poll_data = cursor.fetchone()
    cursor.close()

    if not poll_data:
        flash("Poll not found.")
        return redirect(url_for('polls'))

    # Check if the user has already voted on this poll
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM poll_results WHERE user_id = %s AND poll_id = %s", (session['user_id'], poll_id))
    existing_vote = cursor.fetchone()
    cursor.close()

    if existing_vote:
        flash("You have already voted on this poll.")
        return redirect(url_for('polls'))  # Redirect to polls page or display a message

    form = PollForm()

    if form.validate_on_submit():
        selected_option = form.option.data

        cursor = mysql.connection.cursor()
        try:
            cursor.execute("INSERT INTO poll_results (user_id, poll_id, selected_option) VALUES (%s, %s, %s)",
                           (session['user_id'], poll_id, selected_option))
            mysql.connection.commit()
            cursor.close()
            flash("Your vote has been recorded. Thank you!")
            return redirect(url_for('poll_results'))
        except Exception as e:
            print("Error:", e)
            mysql.connection.rollback()
            cursor.close()
            flash("An error occurred while recording your vote.")
            return redirect(url_for('polls'))

    options = [poll_data[2], poll_data[3], poll_data[4], poll_data[5]]

    return render_template('poll.html', poll=poll_data, options=options, form=form)




@app.route('/poll_results')
def poll_results():
    if 'user_id' not in session:
        flash("Please log in to view the poll results.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor()
    
    # Retrieve the list of poll IDs the user has voted on
    cursor.execute("SELECT DISTINCT poll_id FROM poll_results WHERE user_id = %s", (user_id,))
    voted_polls = [row[0] for row in cursor.fetchall()]

    poll_results = {}  # Initialize an empty dictionary to store results

    # Retrieve results for each poll the user has voted on
    for poll_id in voted_polls:
        cursor.execute("SELECT question FROM polls WHERE poll_id = %s", (poll_id,))
        question = cursor.fetchone()[0]

        cursor.execute("SELECT selected_option, COUNT(*) as vote_count FROM poll_results WHERE poll_id = %s GROUP BY selected_option", (poll_id,))
        options_data = cursor.fetchall()

        options = {}
        for option, vote_count in options_data:
            options[option] = vote_count
        
        poll_results[question] = options

    cursor.close()
    
    return render_template('poll_results.html', poll_results=poll_results)






@app.route('/polls/<int:poll_id>')
def poll_page(poll_id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM polls WHERE poll_id = %s", (poll_id,))
    poll_data = cursor.fetchone()
    cursor.close()

    if not poll_data:
        flash("Poll not found.")
        return redirect(url_for('polls'))

    options = [poll_data['option1'], poll_data['option2'], poll_data['option3'], poll_data['option4']]

    return render_template('poll.html', poll=poll_data, options=options)






@app.route('/vote/<int:poll_id>', methods=['POST'])
def vote(poll_id):
    if 'user_id' not in session:
        flash("Please log in to vote.")
        return redirect(url_for('login'))

    selected_option = request.form.get('option')

    # Generate OTP
    otp = totp.now()

    # Store OTP in session for verification
    session['otp'] = otp

    # Send OTP via email
    send_otp_email(session['email'], otp)

    # Store poll_id and selected_option in session for recording vote after OTP verification
    session['vote_data'] = {'poll_id': poll_id, 'selected_option': selected_option}

    # Redirect to OTP verification page
    return redirect(url_for('verify_vote_otp'))

@app.route('/verify_vote_otp', methods=['GET', 'POST'])
def verify_vote_otp():
    if 'otp' not in session:
        flash("Please vote first.")
        return redirect(url_for('polls'))

    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session['otp']:
            # OTP verification successful, record the vote
            vote_data = session.pop('vote_data', None)
            if vote_data:
                cursor = mysql.connection.cursor()
                try:
                    cursor.execute("INSERT INTO poll_results (user_id, poll_id, selected_option) VALUES (%s, %s, %s)",
                                   (session['user_id'], vote_data['poll_id'], vote_data['selected_option']))
                    mysql.connection.commit()
                    cursor.close()
                    flash("Your vote has been recorded. Thank you!")
                    return redirect(url_for('poll_results'))
                except Exception as e:
                    print("Error:", e)
                    mysql.connection.rollback()
                    cursor.close()
                    flash("An error occurred while recording your vote.")
                    return redirect(url_for('polls'))
            else:
                flash("Vote data not found.")
                return redirect(url_for('polls'))
        else:
            flash("OTP verification failed. Please try again.")

    return render_template('verify_vote_otp.html')



@app.route('/create_poll', methods=['GET', 'POST'])
def create_poll():
    # Check if the user is logged in and if the email matches the specified email
    if 'email' in session and session['email'] == 'dhrumildholakia66@gmail.com':
        if request.method == 'POST':
            question = request.form['question']
            option1 = request.form['option1']
            option2 = request.form['option2']
            option3 = request.form['option3']
            option4 = request.form['option4']

            # Insert the new poll into the database
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT INTO polls (question, option1, option2, option3, option4) VALUES (%s, %s, %s, %s, %s)",
                           (question, option1, option2, option3, option4))
            mysql.connection.commit()
            cursor.close()

            flash("New poll created successfully!")
            return redirect(url_for('polls'))

        return render_template('create_poll.html')
    else:
        # If the user is not authorized, show an error message and redirect
        flash("You are not authorized to create a poll.")
        return redirect(url_for('polls'))




if __name__ == '__main__':
    app.run(debug=True,port=1000)



