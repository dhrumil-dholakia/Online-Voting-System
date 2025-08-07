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
