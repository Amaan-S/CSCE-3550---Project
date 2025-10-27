# CSCE-3550---Project1
Project 1 files are included above

Please note that AI was used to develop the JWKS server. This was my first exposure to JSON Web Key Sets and JSON
web tokens, so I relied heavily on AI (chatGPT to be specific) to help me formulate my thoughts about how the
server was meant to function according to the assignment requirements. First I had to specify that the language I wanted to use was python. And after that I specified that I wanted the following features in the JWKS server:


1) Key generation in RSA pairs with an associate KeyID and expiry timestamps
2) Web server that serves HTTP on port 8080 that had a RESTful JWKS endpoint serving public keys in
   JWKS format (where only valid keys were served), and an /autH endpoint that returned unexpired sined JWT on
   a POST request.


At first, ChatGPT returned python code that built the requests with a psql connection, but I shot down
that attempt down by mentioning that I wanted a pure python program to fulfill the requirements.
I then took the generated code and adjusted it to take requests constantly until the server was stopped by
hitting the enter key. I took the time to then understand the code that was generated and look through it
line-by-line to ensure that It matched the requirements of the JWKS server as desired in project 1.
As I took the time to understand why certain lines of code were generated, I then commented the lines
I felt needed explaination so that I could build up the server later on easir. Afterward, I ran the
gradebot program on the python code and got the score depicted in the .png file. 

# CSCE-3550---Project2
Project 2 files are included above alongside the original project 1 files

As opposed to project 1, I opted to use the reference Project 1 code in the zip file provided in the assignment to ensure that I had a solid foundation to get a good gradebot score. I had some previous experience using sqlmodel, sqlalchemy, and MySQL with postgress, so the syntax on how to do a majority of the functionality was very familiar to me. I didn't have to use AI that often to complete project 2, however I did use it at times to understand why the database was now populating as expecting. I would past some of the very lengthy error messages to the AI and used the feedback it gave me to narrow down the issue I was facing within the next 10-20 minutes. I used AI moderately during debugging, just because at the time I was developing I wanted to expedite the debugging process as much as possible. 

After getting my gradebot score, for the test cases, however, I essentially used AI throughout. I essentially just copied the project 2 code and asked it to make a test case file that utilized pytest. I essentially just wanted to get awarded the points in the rubric for the test case file (Test2.py for project 2) for at least being present. 

I used python version 3.13 for the devlopment of project2 and developed it on a system running Windows. No special frameworks were used to develop the project itself.

To Setup the server to run it locally simply type the following command once you have cloned the repository:

**python3 Project2.py**

that command will run the server. Then you can run gradebot as normal to verify the gradebot screenshot accuracy already provided in the repository (GRADEBOT_project1.png).
