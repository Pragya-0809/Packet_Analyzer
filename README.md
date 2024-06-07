Pre requisites:-

1. Make sure you have installed python(used version 3.12.2) in your system.


2. Make sure your system is connected via Wi-Fi or Ethernet cable with proper internet connection
	If its connected via Wi-Fi new/graph/data3.py line 178 should be "sniff(prn=packet_callback, timeout=dur, iface='Wi-Fi')"
	If its connected via Ethernet cable new/graph/data3.py line 178 should be "sniff(prn=packet_callback, timeout=dur, iface='Ethernet')"

2. WireShark appication must be installed.


3. Install Django (used version 5.0.2) in your system.
             pip install django

4. In your vs code terminal install joblib using
             pip install joblib

5. Install sklearn
            pip install scikit-learn

6. Install the scapy library
           pip install scapy

7. Install numpy library
          pip install numpy

8. Install Matplotlib library
          pip install matplotlib

9. Install pandas library
          pip install pandas

10. Install setuptools package
	  pip install setuptools

Steps to Access this project:-

1. For the project to run make sure you are currently in the 'Django/new' folder. If you are in Django folder move to new by:-
              cd new


2. Run your project using :-
              python manage.py runserver


3. After this you will recieve a url, ctrl+click to view our website.



Description of our website:-

1. HOME PAGE:- This is the landing page of our website. You can navigate to various pages of our websites using this.
   
2. VISUALIZE PAGE:- This page allows the user to view graphical representation of packet information.

3. DASHBOARD PAGE:- This page allows the user to view the graph of packet features.

4. ABOUT PAGE:- This is the page which contains details of our website.

5. CREATE ACCOUNT PAGE:- User can create account at this page. Once the account is created user will be redirected to Home page.

6. LOGIN PAGE:- If the user is already registered to our website he/she can directly login from here and get redirected to the Home page, if not then they will have to create an account first by clicking on Create Account and then it will directed to the home page.

         
